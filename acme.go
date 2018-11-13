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
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"golang.org/x/crypto/acme"
)

const (
	// 2048-bit private keys
	keyBits = 2048

	privateKeyType = "RSA PRIVATE KEY"
)

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

// PrivateKeyToPEM takes an RSA private key and returns the PEM-encoded bytes
func PrivateKeyToPEM(key *rsa.PrivateKey) []byte {
	block := &pem.Block{
		Type:  privateKeyType,
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}

	return pem.EncodeToMemory(block)
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
	auth.PrivateKey = string(PrivateKeyToPEM(key))

	logger.Info("Registered new user", "url", auth.URI)

	return nil
}
