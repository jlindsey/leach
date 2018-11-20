package main

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"strings"
	"sync"

	consul "github.com/hashicorp/consul/api"
	"github.com/imdario/mergo"
)

func getAllSites(ctx context.Context, kv *consul.KV, prefix string, config *Config) ([]*SiteConfig, error) {
	sitePath := fmt.Sprintf("%s/%s/", prefix, consulSitesPrefix)
	pairs, err := getAllPairsInPrefix(ctx, kv, sitePath)
	if err != nil {
		return nil, err
	}

	configs := make([]*SiteConfig, len(pairs))
	for i, pair := range pairs {
		config, err := getSiteConfig(ctx, kv, pair, config)
		if err != nil {
			return nil, err
		}

		configs[i] = config
	}

	return configs, nil
}

func getAllCerts(ctx context.Context, kv *consul.KV, prefix string) ([]*x509.Certificate, error) {
	pkiPath := fmt.Sprintf("%s/%s/", prefix, consulPKIPrefix)
	pairs, err := getAllPairsInPrefix(ctx, kv, pkiPath)
	if err != nil {
		return nil, err
	}

	certs := make([]*x509.Certificate, len(pairs)/2)
	for i, pair := range pairs {
		if strings.HasSuffix(pair.Key, "-key.pem") {
			continue
		}

		block, _ := pem.Decode(pair.Value)
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}

		certs[i] = cert
	}

	return certs, nil
}

func getAllRevokes(ctx context.Context, kv *consul.KV, prefix string, config *Config) ([]*RevokeConfig, error) {
	revPath := fmt.Sprintf("%s/%s/", prefix, consulRevokePrefix)
	pairs, err := getAllPairsInPrefix(ctx, kv, revPath)
	if err != nil {
		return nil, err
	}

	revs := make([]*RevokeConfig, len(pairs))
	for i, pair := range pairs {
		if len(pair.Value) == 0 {
			pair.Value = json.RawMessage(`{}`)
		}

		rev := new(RevokeConfig)
		err = json.Unmarshal(pair.Value, rev)
		if err != nil {
			return nil, err
		}

		siteKey := strings.Replace(pair.Key, consulRevokePrefix, consulSitesPrefix, 1)
		sitePair, _, err := kv.Get(siteKey, nil)
		if err != nil {
			return nil, err
		}

		if sitePair == nil {
			baseLogger.Warn("Revoke with no associated site", "key", pair.Key)
			_, err = kv.Delete(pair.Key, nil)
			if err != nil {
				return nil, err
			}
			continue
		}

		siteConfig, err := getSiteConfig(ctx, kv, sitePair, config)
		if err != nil {
			return nil, err
		}
		rev.SiteConfig = siteConfig

		crt, err := getStoredCert(ctx, kv, prefix, rev.FQDN)
		if err != nil {
			return nil, err
		}
		rev.Cert = crt

		revs[i] = rev
	}

	outRevs := make([]*RevokeConfig, 0)
	for _, rev := range revs {
		if rev == nil {
			continue
		}

		outRevs = append(outRevs, rev)
	}

	return outRevs, nil
}

func getAllPairsInPrefix(ctx context.Context, kv *consul.KV, path string) ([]*consul.KVPair, error) {
	logger := baseLogger.Named("getAllPairsInPrefix").With("prefix", path)

	logger.Trace("Fetching key list")

	rawKeys, _, err := kv.Keys(path, "/", nil)
	if err != nil {
		return nil, err
	}

	keys := make([]string, 0)

	for _, k := range rawKeys {
		if k == path {
			continue
		}

		keys = append(keys, k)
	}

	logger.Trace("Got keys", "keys", keys)

	ops := make(consul.KVTxnOps, len(keys))
	for i, key := range keys {
		ops[i] = &consul.KVTxnOp{
			Verb: consul.KVGet,
			Key:  key,
		}
	}

	q := new(consul.QueryOptions)
	q = q.WithContext(ctx)

	ok, resp, _, err := kv.Txn(ops, q)
	if err != nil {
		return nil, err
	}

	if !ok {
		return nil, fmt.Errorf("Transaction rolled back: %v", resp.Errors)
	}

	return resp.Results, nil
}

func getStoredCert(ctx context.Context, kv *consul.KV, prefix, fqdn string) (*x509.Certificate, error) {
	certPath := fmt.Sprintf("%s/%s/%s-cert.pem", prefix, consulPKIPrefix, fqdn)

	opts := new(consul.QueryOptions)
	opts = opts.WithContext(ctx)

	pair, _, err := kv.Get(certPath, opts)
	if err != nil {
		return nil, err
	}

	if pair == nil {
		return nil, nil
	}

	block, _ := pem.Decode(pair.Value)

	return x509.ParseCertificate(block.Bytes)
}

func storeCertAndKey(kv *consul.KV, prefix, fqdn string, crt CertificatePEM, key PrivateKeyPEM) error {
	keyPath := fmt.Sprintf("%s/%s/%s-key.pem", prefix, consulPKIPrefix, fqdn)
	crtPath := fmt.Sprintf("%s/%s/%s-cert.pem", prefix, consulPKIPrefix, fqdn)

	ops := consul.KVTxnOps{
		&consul.KVTxnOp{
			Verb:  consul.KVSet,
			Key:   keyPath,
			Value: key,
		},
		&consul.KVTxnOp{
			Verb:  consul.KVSet,
			Key:   crtPath,
			Value: crt,
		},
	}

	ok, resp, _, err := kv.Txn(ops, nil)
	if err != nil {
		return err
	}

	if !ok {
		return fmt.Errorf("Transaction rolled back: %v", resp)
	}

	return nil
}

func getSiteConfig(ctx context.Context, kv *consul.KV, sitePair *consul.KVPair, config *Config) (*SiteConfig, error) {
	key := sitePair.Key
	split := strings.Split(key, "/")
	fqdn := split[len(split)-1]

	logger := baseLogger.Named("getSiteConfig").With("key", key)

	logger.Trace("Fetching site config")

	if len(sitePair.Value) == 0 {
		// If the key is empty, make it an empty JSON object so we can just decode
		// as normal without special logic.
		sitePair.Value = json.RawMessage(`{}`)
	}

	siteConfig := SiteConfig{}
	embConfig := Config{}
	if err := json.Unmarshal(sitePair.Value, &embConfig); err != nil {
		return nil, err
	}

	if err := json.Unmarshal(sitePair.Value, &siteConfig); err != nil {
		return nil, err
	}

	siteConfig.mut = new(sync.Mutex)
	if siteConfig.ACMEAuthorizationURLs == nil {
		siteConfig.ACMEAuthorizationURLs = make(map[string]string)
	}
	if siteConfig.DNSProviderIDs == nil {
		siteConfig.DNSProviderIDs = make(map[string]string)
	}

	logger.Trace("Checking for stored internal vars")
	intConfig := SiteConfigInternal{}
	intKey := strings.Replace(key, consulSitesPrefix, consulVarPrefix, 1)

	intPair, _, err := kv.Get(intKey, nil)
	if err != nil {
		return nil, err
	}

	if intPair != nil {
		err = json.Unmarshal(intPair.Value, &intConfig)
		if err != nil {
			return nil, err
		}

		logger.Trace("Found vars")

		siteConfig.SiteConfigInternal = intConfig
	}

	siteConfig.FQDN = fqdn

	baseLogger.Trace("Got site config", "key", key, "siteConfig", siteConfig)

	if err = mergo.Merge(&embConfig, config); err != nil {
		return nil, err
	}

	siteConfig.Config = embConfig

	baseLogger.Trace("Merged config", "key", key, "siteConfig", siteConfig)

	return &siteConfig, nil
}

func setSiteConfig(ctx context.Context, kv *consul.KV, key string, siteConfig *SiteConfig) error {
	varEncoded, err := json.Marshal(siteConfig.SiteConfigInternal)
	if err != nil {
		return err
	}

	varKey := strings.Replace(key, consulSitesPrefix, consulVarPrefix, 1)
	pair := consul.KVPair{
		Key:   varKey,
		Value: varEncoded,
	}

	_, err = kv.Put(&pair, nil)
	if err != nil {
		return err
	}

	return nil
}

func getAuth(ctx context.Context, kv *consul.KV, prefix string) (*Auth, error) {
	path := fmt.Sprintf("%s/%s", prefix, consulAuthKey)
	opts := new(consul.QueryOptions)
	opts = opts.WithContext(ctx)
	pair, _, err := kv.Get(path, opts)
	if err != nil {
		return nil, err
	}

	if pair == nil {
		// It's fine if there's no auth data, just return nil
		return nil, nil
	}

	auth := new(Auth)
	if err = json.Unmarshal(pair.Value, auth); err != nil {
		return nil, err
	}

	return auth, nil
}

func setAuth(ctx context.Context, kv *consul.KV, prefix string, auth *Auth) error {
	path := fmt.Sprintf("%s/%s", prefix, consulAuthKey)

	encoded, err := json.MarshalIndent(auth, "", "\t")
	if err != nil {
		return err
	}

	data := &consul.KVPair{
		Key:   path,
		Value: encoded,
	}

	opts := new(consul.WriteOptions)
	opts = opts.WithContext(ctx)

	if _, err = kv.Put(data, opts); err != nil {
		return err
	}

	return nil
}
