// Copyright 2018 Josh Lindsey <joshua.s.lindsey@gmail.com>
//
//
//    Licensed under the Apache License, Version 2.0 (the "License");
//    you may not use this file except in compliance with the License.
//    You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
//    Unless required by applicable law or agreed to in writing, software
//    distributed under the License is distributed on an "AS IS" BASIS,
//    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//    See the License for the specific language governing permissions and
//    limitations under the License.

package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"net"
	"time"

	"golang.org/x/crypto/acme"
	"golang.org/x/sync/errgroup"
)

const (
	keyBits      = 2048                // 2048-bit private keys
	certDuration = 90 * 24 * time.Hour // LE only offers 90-day certs

	acmeChallengeTTL       = 30
	acmeChallengeSubdomain = "_acme-challenge"

	// PEM header types
	privateKeyType = "RSA PRIVATE KEY"
	certType       = "CERTIFICATE"

	authStatusValid = "valid"
)

// CertificatePEM is a byte slice representing an x509 Certificate in PEM encoding.
type CertificatePEM []byte

// PrivateKeyPEM is a byte slice representing an RSA Private Key in PEM encoding.
type PrivateKeyPEM []byte

// GenPrivateKey generates a new RSA private key
func GenPrivateKey() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, keyBits)
}

// PrivateKeyFromPEM parses the pem-encoded input bytes into an rsa.PrivateKey instance.
// Accepts either a string or []byte input.
func PrivateKeyFromPEM(pemKey interface{}) (*rsa.PrivateKey, error) {
	var pemKeyBytes []byte
	switch v := pemKey.(type) {
	case []byte:
		pemKeyBytes = v
	case string:
		pemKeyBytes = []byte(v)
	default:
		return nil, fmt.Errorf("unknown type for pem key bytes: %T", pemKey)
	}

	block, rest := pem.Decode(pemKeyBytes)
	if len(rest) > 0 {
		baseLogger.Named("acme").Warn("Leftover bytes when decoding private key pem: %#v", rest)
	}

	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

// ToPEM takes an RSA private key, a DER-formatted []byte (for a single Certificate), or
// a slice of DER-formatted []byte ([][]byte, for a Certificate + chain) and returns the
// PEM-encoded bytes.
func ToPEM(data interface{}) ([]byte, error) {
	switch v := data.(type) {
	case *rsa.PrivateKey:
		block := &pem.Block{
			Type:  privateKeyType,
			Bytes: x509.MarshalPKCS1PrivateKey(v),
		}
		return pem.EncodeToMemory(block), nil
	case [][]byte:
		// Cert + chain
		var buf bytes.Buffer
		for _, b := range v {
			block := &pem.Block{
				Type:  certType,
				Bytes: b,
			}

			buf.Write(pem.EncodeToMemory(block))
		}
		return buf.Bytes(), nil
	case []byte:
		// Cert alone
		block := &pem.Block{
			Type:  certType,
			Bytes: v,
		}
		return pem.EncodeToMemory(block), nil
	}

	return nil, fmt.Errorf("unknown data type to convert to PEM: %T", data)
}

// DoAuth either registers a new account with LE or checks the registration of an existing one.
// For new accounts, provide the Auth param with only the Email field filled in. The acme.Client
// and Auth params will be modified with the generated private key.
func DoAuth(ctx context.Context, client *acme.Client, auth *Auth) error {
	logger := baseLogger.Named("acme").Named("auth").With("email", auth.Email)

	if auth.PrivateKey != "" {
		logger.Debug("Existing registration found, checking validity")
		key, err := PrivateKeyFromPEM(auth.PrivateKey)
		if err != nil {
			return err
		}

		client.Key = key
		_, err = client.GetReg(ctx, auth.URI)
		if err != nil {
			return err
		}

		logger.Info("Valid registration")
		return nil
	}

	logger.Debug("New registration found")
	key, err := GenPrivateKey()
	if err != nil {
		return err
	}

	client.Key = key
	acct := &acme.Account{
		Contact: []string{auth.Email},
	}
	acct, err = client.Register(ctx, acct, acme.AcceptTOS)
	if err != nil {
		return err
	}

	auth.URI = acct.URI
	pemKey, err := ToPEM(key)
	if err != nil {
		return err
	}
	auth.PrivateKey = string(pemKey)

	logger.Info("Registered new user", "url", auth.URI)

	return nil
}

// CreateACMECert creates a new LE cert and key. It returns the cert and private key in pem-encoded format.
// The provided siteConfig is updated in-place with the internal info to track.
func CreateACMECert(ctx context.Context, client *acme.Client, siteConfig *SiteConfig) (CertificatePEM, PrivateKeyPEM, error) {
	logger := baseLogger.Named("acme").Named("create").With("fqdn", siteConfig.FQDN)

	provider, err := siteConfig.GetProvider()
	if err != nil {
		return nil, nil, err
	}

	auths := make(map[string]*acme.Authorization, len(siteConfig.ExtraNames)+1)

	if len(siteConfig.ACMEAuthorizationURLs) > 0 {
		logger.Info("Checking existing authorizations")

		for fqdn, authURL := range siteConfig.ACMEAuthorizationURLs {
			l := logger.With("for", fqdn, "url", authURL)
			l.Trace("Checking auth")

			auth, err := client.GetAuthorization(ctx, authURL)
			if err != nil {
				l.Error("Error checking auth", "err", err)
				siteConfig.RemoveAuthorizationURL(fqdn)
			}

			if auth.Status == authStatusValid {
				l.Trace("Auth already valid")
				auths[fqdn] = auth
			}
		}
	}

	// Check for base FQDN auth and request if missing
	if _, ok := auths[siteConfig.FQDN]; !ok {
		logger.Info("Requesting authorization", "for", siteConfig.FQDN)
		auth, err := client.Authorize(ctx, siteConfig.FQDN)
		if err != nil {
			return nil, nil, err
		}

		auths[siteConfig.FQDN] = auth
	}

	// Check for extra FQDNs auths and request if missing
	for _, fqdn := range siteConfig.ExtraNames {
		if _, ok := auths[fqdn]; !ok {
			logger.Info("Requesting authorization", "for", fqdn)
			auth, err := client.Authorize(ctx, fqdn)
			if err != nil {
				return nil, nil, err
			}

			auths[fqdn] = auth
		}
	}

	fqdnsToAuth := make([]string, 0)
	for fqdn := range auths {
		fqdnsToAuth = append(fqdnsToAuth, fqdn)
	}

	logger.Debug("Requesting auths", "for", fqdnsToAuth)

	var g errgroup.Group

	for fqdn, auth := range auths {
		g.Go(func() error {
			innerLogger := logger.With("auth", auth.URI, "for", fqdn)

			// Sometimes we can get into a bad state where the URL stored for an FQDN's auth
			// will report as invalid but when we request a "new" auth it will be valid,
			// so check again here.
			if auth.Status == authStatusValid {
				innerLogger.Info("Auth already valid")
				return nil
			}

			var challenge *acme.Challenge
			for _, chal := range auth.Challenges {
				if chal.Type == "dns-01" {
					innerLogger.Debug("Found DNS-01 challenge", "challenge", chal)
					challenge = chal
					break
				}
			}

			if challenge == nil {
				return fmt.Errorf("No DNS challenge found for auth: %s", fqdn)
			}

			txtToken, err := client.DNS01ChallengeRecord(challenge.Token)
			if err != nil {
				return err
			}

			var record TXTRecord
			dnsID, ok := siteConfig.DNSProviderIDs[fqdn]
			if ok {
				record, err = provider.Get(dnsID)
				if err != nil {
					return err
				}

				innerLogger.Trace("Record found")
			}

			if record != nil && record.Text() != txtToken {
				innerLogger.Trace("Record exists but does not match, recreating")
				err = provider.Delete(record.ID())
				if err != nil {
					return err
				}
				siteConfig.RemoveDNSID(fqdn)
				record = nil
			}

			if record == nil {
				protoRecord := &GenericTXTRecord{
					name: fmt.Sprintf("%s.%s", acmeChallengeSubdomain, fqdn),
					text: txtToken,
				}

				innerLogger.Debug("Creating DNS record", "record", protoRecord)

				id, err := provider.Create(protoRecord)
				if err != nil {
					return err
				}

				siteConfig.AddDNSID(fqdn, id)
			} else {
				logger.Trace("Record matches already")
			}

			txtFQDN := fmt.Sprintf("%s.%s", acmeChallengeSubdomain, fqdn)
			innerLogger.Debug("Waiting for DNS", "txtFQDN", txtFQDN)

			for {
				vals, err := net.LookupTXT(txtFQDN)
				if err != nil || len(vals) == 0 || vals[0] != txtToken {
					innerLogger.Trace("Still waiting", "err", err, "vals", vals)
					time.Sleep(10 * time.Second)
					continue
				}

				break
			}

			challenge, err = client.Accept(ctx, challenge)
			if err != nil {
				return err
			}
			innerLogger.Debug("Accepted DNS-01 challenge")

			try := 1
			maxTries := 5
			sleep := time.Second * 30
			for {
				goodAuth, err := client.WaitAuthorization(ctx, auth.URI)
				if err != nil {
					if try <= maxTries {
						innerLogger.Info("Got error from WaitAuthorizaiton", "err", err, "attempt", try, "maxAttemps", maxTries)
						time.Sleep(sleep)
						try++
						continue
					}

					return err
				}

				innerLogger.Info("Auth accepted", "authz", goodAuth.Identifier)

				siteConfig.AddAuthorizationURL(fqdn, goodAuth.URI)

				break
			}

			return nil
		})
	}

	err = g.Wait()
	if err != nil {
		return nil, nil, err
	}

	privateKey, err := GenPrivateKey()
	if err != nil {
		return nil, nil, err
	}

	req := &x509.CertificateRequest{
		SignatureAlgorithm: x509.SHA256WithRSA,
		Subject: pkix.Name{
			Country:            siteConfig.Ident.Country,
			Province:           siteConfig.Ident.Province,
			Locality:           siteConfig.Ident.Locality,
			Organization:       siteConfig.Ident.Organization,
			OrganizationalUnit: siteConfig.Ident.OrganizationalUnit,
			CommonName:         siteConfig.FQDN,
		},
	}

	if len(siteConfig.ExtraNames) > 0 {
		req.DNSNames = siteConfig.ExtraNames
	}

	csr, err := x509.CreateCertificateRequest(rand.Reader, req, privateKey)
	if err != nil {
		return nil, nil, err
	}

	logger.Info("Generated CSR")

	crt, uri, err := client.CreateCert(ctx, csr, certDuration, true)
	if err != nil {
		return nil, nil, err
	}

	siteConfig.ACMEDownloadURL = uri

	logger.Info("Got cert from ACME", "certURL", uri)

	pkPem, err := ToPEM(privateKey)
	if err != nil {
		return nil, nil, err
	}

	crtPem, err := ToPEM(crt)
	if err != nil {
		return nil, nil, err
	}

	return CertificatePEM(crtPem), PrivateKeyPEM(pkPem), nil
}
