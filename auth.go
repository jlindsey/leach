package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"

	consul "github.com/hashicorp/consul/api"
	"golang.org/x/crypto/acme"
)

type authInfo struct {
	Email string `json:"email"`
	Key   string `json:"key"`
	URL   string `json:"url"`
}

func getAcmeClient(ctx context.Context) (*acme.Client, error) {
	var (
		rsaKey *rsa.PrivateKey
		err    error
	)

	consulClient := ctx.Value(ctxConsulClient).(*consul.Client)
	consulPrefix := ctx.Value(ctxConsulPrefix).(string)
	leEndpoint := ctx.Value(ctxLetsEncryptEndpoint).(string)

	kv := consulClient.KV()
	key := fmt.Sprintf("%s/%s", consulPrefix, authKey)
	pair, _, err := kv.Get(key, nil)
	if err != nil {
		return nil, err
	}

	if pair == nil {
		return nil, fmt.Errorf("Missing config at %s", key)
	}

	var auth authInfo
	err = json.Unmarshal(pair.Value, &auth)
	if err != nil {
		return nil, err
	}

	if len(auth.Email) == 0 {
		return nil, fmt.Errorf("Requires at least an email in auth key")
	}

	if len(auth.Key) == 0 {
		rsaKey, err = rsa.GenerateKey(rand.Reader, keyBits)
		if err != nil {
			return nil, err
		}

		block := &pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(rsaKey),
		}

		auth.Key = string(pem.EncodeToMemory(block))
	} else {
		block, _ := pem.Decode([]byte(auth.Key))
		rsaKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
	}

	client := &acme.Client{Key: rsaKey, DirectoryURL: leEndpoint}

	if len(auth.URL) > 0 {
		acct, err := client.GetReg(ctx, auth.URL)
		if err != nil {
			return nil, err
		}

		fmt.Printf("Stored auth is valid: %#v", acct)
	} else {
		acct, err := client.Register(ctx, &acme.Account{
			Contact: []string{fmt.Sprintf("mailto:%s", auth.Email)},
		}, acme.AcceptTOS)
		if err != nil {
			return nil, err
		}

		auth.URL = acct.URI
	}

	encoded, err := json.Marshal(auth)
	if err != nil {
		return nil, err
	}

	pair = &consul.KVPair{
		Key:   key,
		Value: encoded,
	}

	_, err = kv.Put(pair, nil)
	if err != nil {
		return nil, err
	}

	return client, nil
}
