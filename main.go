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
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	consul "github.com/hashicorp/consul/api"
	"github.com/hashicorp/go-hclog"
	"github.com/imdario/mergo"
	"golang.org/x/crypto/acme"
	"golang.org/x/sync/errgroup"
	"gopkg.in/urfave/cli.v1"
)

const (
	defaultConsulAddr   = "127.0.0.1:8500"
	defaultConsulPrefix = "leach"
	defaultLogLevel     = "INFO"

	defaultRenew = 30

	consulConfigKey    = "config"
	consulAuthKey      = "auth"
	consulSitesPrefix  = "sites"
	consulVarPrefix    = "var"
	consulPKIPrefix    = "pki"
	consulRevokePrefix = "revoke"
)

var (
	// Version is the version of the app, provided by ldflags when building for release.
	Version = "0.0.0"
	// GitSHA is the commit of the build.
	GitSHA = ""
)

var (
	baseLogger              hclog.Logger
	watchers                map[string]*KeyWatcher
	working                 map[string]context.CancelFunc
	watchersMut, workingMut *sync.RWMutex
	sitesChan               chan *consul.KVPair
	eg                      *errgroup.Group
)

func init() {
	watchersMut = new(sync.RWMutex)
	workingMut = new(sync.RWMutex)
	watchers = make(map[string]*KeyWatcher)
	working = make(map[string]context.CancelFunc)
	sitesChan = make(chan *consul.KVPair, 32)
}

func main() {
	app := cli.NewApp()
	app.Usage = "Lets Encrypt Automated Certificate Handler"
	app.Version = fmt.Sprintf("%s (%s)", Version, GitSHA)
	app.HideHelp = true
	app.UsageText = "leach [options]"
	app.Action = run
	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:   "consul-addr, a",
			Value:  defaultConsulAddr,
			Usage:  "Connect to Consul running at `ADDR`",
			EnvVar: "CONSUL_ADDR",
		},
		cli.StringFlag{
			Name:   "consul-prefix, c",
			Value:  defaultConsulPrefix,
			Usage:  "Consul KV store `PREFIX` for configuration and storage",
			EnvVar: "CONSUL_PREFIX",
		},
		cli.StringFlag{
			Name:   "acme-url, u",
			Value:  acme.LetsEncryptURL,
			Usage:  "URL to the ACME directory to use",
			EnvVar: "ACME_URL",
		},
		cli.StringFlag{
			Name:   "log-level, l",
			Usage:  "Set the logger to the specified `LEVEL`",
			Value:  defaultLogLevel,
			EnvVar: "LOG_LEVEL",
		},
		cli.BoolFlag{
			Name:  "help, h",
			Usage: "show help",
		},
	}

	err := app.Run(os.Args)
	if err != nil {
		baseLogger.Error(err.Error())
		os.Exit(1)
	}
}

func run(c *cli.Context) error {
	if c.Bool("help") {
		cli.ShowAppHelpAndExit(c, 0)
		return nil
	}

	rootCtx, rootCancel := context.WithCancel(context.Background())
	defer rootCancel()

	prefix := c.String("consul-prefix")
	consulAddr := c.String("consul-addr")

	baseLogger = hclog.New(&hclog.LoggerOptions{
		Name:   prefix,
		Level:  hclog.LevelFromString(c.String("log-level")),
		Output: os.Stdout,
	})

	baseLogger.Trace("Consul", "addr", consulAddr, "prefix", prefix)

	consulConfig := &consul.Config{
		Address: consulAddr,
	}
	consulClient, err := consul.NewClient(consulConfig)
	if err != nil {
		return err
	}
	kv := consulClient.KV()

	g, ctx := errgroup.WithContext(rootCtx)

	config := new(Config)
	configPath := fmt.Sprintf("%s/%s", prefix, consulConfigKey)
	configWatcher := NewKeyWatcher(rootCtx, kv, configPath)
	g.Go(configWatcher.Watch)
	g.Go(func() error {
		for {
			select {
			case <-ctx.Done():
				return nil
			case pair := <-configWatcher.Data():
				if err := json.Unmarshal(pair.Value, config); err != nil {
					return err
				}

				if config.Renew == 0 {
					config.Renew = defaultRenew
				}

				baseLogger.Trace("Got config", "config", config)
			}
		}
	})

	// Wait for good initial config
	for {
		if config != nil {
			baseLogger.Trace("Waiting for initial config")
			time.Sleep(time.Second)
			break
		}
	}

	auth, err := getAuth(rootCtx, kv, prefix)
	if err != nil {
		return err
	}
	if auth == nil {
		// New Login
		auth = &Auth{Email: config.Email}
	}

	directoryURL := c.String("acme-url")
	baseLogger.Debug("Using directory", "url", directoryURL)

	acmeClient := &acme.Client{DirectoryURL: directoryURL}
	err = DoAuth(rootCtx, acmeClient, auth)
	if err != nil {
		return err
	}

	err = setAuth(rootCtx, kv, prefix, auth)
	if err != nil {
		return err
	}

	g.Go(func() error { return watchSiteKeys(ctx, prefix, kv, acmeClient, config) })
	g.Go(func() error { return handleSiteUpdates(ctx, kv, acmeClient, config) })

	err = g.Wait()
	baseLogger.Trace("Primary errgroup returned")
	close(sitesChan)
	return err
}

func watchSiteKeys(ctx context.Context, prefix string, kv *consul.KV, acmeClient *acme.Client, config *Config) error {
	logger := baseLogger.Named("watchSiteKeys")
	sitesPath := fmt.Sprintf("%s/%s/", prefix, consulSitesPrefix)
	siteKeysWatcher := NewKeyWatcher(ctx, kv, sitesPath)

	g, ctx := errgroup.WithContext(ctx)
	g.Go(siteKeysWatcher.Watch)

	g.Go(func() error {
		for {
			var (
				siteKeysPair *consul.KVPair
				ok           bool
			)

			select {
			case <-ctx.Done():
				logger.Trace("context done")
				return nil
			case siteKeysPair, ok = <-siteKeysWatcher.Data():
				if !ok {
					logger.Debug("Site keys watcher chan closed")
					return nil
				}
			}

			siteKeys := make([]string, 0)
			err := json.Unmarshal(siteKeysPair.Value, &siteKeys)
			if err != nil {
				return err
			}

			logger.Debug("Updated sites", "keys", siteKeys)

		OUTER_NEW:
			for _, siteKey := range siteKeys {
				watchersMut.RLock()
				for existing := range watchers {
					if existing == siteKey {
						watchersMut.RUnlock()
						continue OUTER_NEW
					}
				}
				watchersMut.RUnlock()

				// New Site
				g.Go(newSiteWatcher(ctx, kv, siteKey))
			}
		}
	})

	err := g.Wait()
	logger.Trace("errgroup returned")
	return err
}

func newSiteWatcher(ctx context.Context, kv *consul.KV, siteKey string) func() error {
	return func() error {
		watcher := NewKeyWatcher(ctx, kv, siteKey)
		watcher.CancelOnMissing = true
		go watcher.Watch()

		watchersMut.Lock()
		watchers[siteKey] = watcher
		watchersMut.Unlock()

		defer func() {
			watchersMut.Lock()
			delete(watchers, siteKey)
			watchersMut.Unlock()
		}()

		for {
			v, dataOK := <-watcher.Data()

			workingMut.RLock()
			cancel, cancelOK := working[siteKey]
			if cancelOK {
				// Cancel work in progress on new data or missing key
				cancel()
			}
			workingMut.RUnlock()

			if !dataOK {
				// Channel closed (key probably deleted)
				break
			}

			sitesChan <- v
		}

		return nil
	}
}

func handleSiteUpdates(ctx context.Context, kv *consul.KV, acmeClient *acme.Client, config *Config) error {
	logger := baseLogger.Named("handleSiteUpdates")

	g, ctx := errgroup.WithContext(ctx)

	g.Go(func() error {
		for {
			var (
				sitePair *consul.KVPair
				ok       bool
			)

			select {
			case <-ctx.Done():
				logger.Trace("context done")
				return nil
			case sitePair, ok = <-sitesChan:
				if !ok {
					logger.Debug("Closed sitesChan")
					return nil
				}
			}

			siteKey := sitePair.Key
			prefix := strings.Split(siteKey, "/")[0]

			innerLogger := logger.With("key", siteKey)
			innerLogger.Trace("Got new site data")

			split := strings.Split(siteKey, "/")
			fqdn := split[len(split)-1]

			cert, err := getStoredCert(kv, prefix, fqdn)
			if err != nil {
				return err
			}

			for {
				// Wait for any currently-working threads to finish
				workingMut.RLock()
				_, isWorking := working[siteKey]
				workingMut.RUnlock()

				if !isWorking {
					break
				}
			}

			if cert == nil {
				// New cert
				innerLogger.Info("Detected new Cert")

				g.Go(func() error {
					logger := innerLogger.Named("createLoop")

					ctx, cancel := context.WithCancel(ctx)
					defer cancel()

					workingMut.Lock()
					working[siteKey] = cancel
					workingMut.Unlock()

					defer func() {
						workingMut.Lock()
						delete(working, siteKey)
						workingMut.Unlock()
					}()

					for {
						select {
						case <-ctx.Done():
							logger.Debug("New data or key missing, abandoning")
							return nil
						default:
						}

						siteConfig, err := getSiteConfig(ctx, kv, sitePair, config)
						if err != nil {
							logger.Error("Unable to load site config", "err", err)
							time.Sleep(5 * time.Second)
							continue
						}

						crt, key, err := CreateACMECert(ctx, acmeClient, siteConfig)
						if err != nil {
							logger.Error("Unable to create new cert", "err", err)
							time.Sleep(5 * time.Second)
							continue
						}

						err = storeCertAndKey(kv, prefix, siteConfig.FQDN, crt, key)
						if err != nil {
							logger.Error("Unable to store new cert", "err", err)
							time.Sleep(5 * time.Second)
							continue
						}

						err = setSiteConfig(ctx, kv, siteKey, siteConfig)
						if err != nil {
							logger.Error("Unable to store updated site key", "err", err)
							time.Sleep(5 * time.Second)
							continue
						}

						// Re-add sitePair to the chan so that it gets picked up again
						// and falls through here to the renew watcher.
						sitesChan <- sitePair
						break
					}

					return nil
				})

				continue
			}

			// Existing cert - check expiration to see if it needs renewing
			logger.Info("Found existing cert", "fqdn", fqdn, "dnsNames", cert.DNSNames, "expiration", cert.NotAfter)

			g.Go(func() error {
				logger := logger.Named("renewWatcher")

				ctx, cancel := context.WithCancel(ctx)
				defer cancel()

				workingMut.Lock()
				working[siteKey] = cancel
				workingMut.Unlock()

				defer func() {
					workingMut.Lock()
					delete(working, siteKey)
					workingMut.Unlock()
				}()

				ticker := time.NewTicker(time.Hour)
				defer ticker.Stop()

				do := func() {
					for {
						logger.Trace("Checking cert expiration")

						siteConfig, err := getSiteConfig(ctx, kv, sitePair, config)
						if err != nil {
							logger.Error("Unable to load site config", "err", err)
							time.Sleep(5 * time.Second)
							continue
						}

						renewDuration := time.Duration(siteConfig.Renew) * 24 * time.Hour
						if cert.NotAfter.Before(time.Now()) || time.Until(cert.NotAfter) <= renewDuration {
							innerLogger.Info("Cert needs renewal")
							crt, key, err := CreateACMECert(ctx, acmeClient, siteConfig)
							if err != nil {
								logger.Error("Unable to create new cert", "err", err)
								time.Sleep(5 * time.Second)
								continue
							}

							err = storeCertAndKey(kv, prefix, siteConfig.FQDN, crt, key)
							if err != nil {
								logger.Error("Unable to store new cert", "err", err)
								time.Sleep(5 * time.Second)
								continue
							}

							err = setSiteConfig(ctx, kv, siteKey, siteConfig)
							if err != nil {
								logger.Error("Unable to store updated site key", "err", err)
								time.Sleep(5 * time.Second)
								continue
							}
						}

						break
					}
				}

				do()

				for {
					select {
					case <-ctx.Done():
						logger.Debug("New data or key missing, abandoning")
						return nil
					case _, ok := <-ticker.C:
						if !ok {
							logger.Trace("ticker closed")
							return nil
						}

						do()
					}
				}
			})
		}
	})

	err := g.Wait()
	logger.Trace("errgroup returned")
	return err
}

func getStoredCert(kv *consul.KV, prefix, fqdn string) (*x509.Certificate, error) {
	certPath := fmt.Sprintf("%s/%s/%s-cert.pem", prefix, consulPKIPrefix, fqdn)

	pair, _, err := kv.Get(certPath, nil)
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
