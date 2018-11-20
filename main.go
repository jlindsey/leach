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
	"fmt"
	"os"
	"sync"
	"time"

	consul "github.com/hashicorp/consul/api"
	"github.com/hashicorp/go-hclog"
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
	baseLogger   hclog.Logger
	watchers     map[string]*KeyWatcher
	watchersMut  *sync.RWMutex
	convergeChan chan struct{}
	eg           *errgroup.Group
)

func init() {
	watchersMut = new(sync.RWMutex)
	watchers = make(map[string]*KeyWatcher)
	convergeChan = make(chan struct{}, 32)
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

	g.Go(func() error { return watchManager(ctx, prefix, kv) })
	g.Go(func() error { return converger(ctx, kv, prefix, acmeClient, config) })

	err = g.Wait()
	baseLogger.Trace("Primary errgroup returned")
	close(convergeChan)
	return err
}

// Watches the "top-level directories" of sites/ pki/ and revoke/ for updates,
// and creates missing KeyWatchers that monitor the individual keys.
func watchManager(ctx context.Context, prefix string, kv *consul.KV) error {
	logger := baseLogger.Named("watchKeys")

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	pkiPath := fmt.Sprintf("%s/%s/", prefix, consulPKIPrefix)
	sitesPath := fmt.Sprintf("%s/%s/", prefix, consulSitesPrefix)
	revPath := fmt.Sprintf("%s/%s/", prefix, consulRevokePrefix)
	pkiKeysWatcher := NewKeyWatcher(ctx, kv, pkiPath)
	siteKeysWatcher := NewKeyWatcher(ctx, kv, sitesPath)
	revKeysWatcher := NewKeyWatcher(ctx, kv, revPath)

	g, ctx := errgroup.WithContext(ctx)

	g.Go(siteKeysWatcher.Watch)
	g.Go(pkiKeysWatcher.Watch)
	g.Go(revKeysWatcher.Watch)
	g.Go(func() error {
		for {
			var (
				path    string
				keyPair *consul.KVPair
				ok      bool
			)

			select {
			case <-ctx.Done():
				logger.Trace("context done")
				return nil
			case keyPair, ok = <-siteKeysWatcher.Data():
				path = sitesPath
				if !ok {
					logger.Warn("Site keys watcher chan closed, cancelling all watchers!")
					cancel()
					continue
				}
			case keyPair, ok = <-pkiKeysWatcher.Data():
				path = pkiPath
				if !ok {
					logger.Warn("PKI watcher chan closed, cancelling all watchers!")
					cancel()
					continue
				}
			case keyPair, ok = <-revKeysWatcher.Data():
				path = revPath
				if !ok {
					logger.Warn("Revoke watcher chan closed, cancelling all watchers!")
					cancel()
					continue
				}
			}

			keys := make([]string, 0)
			err := json.Unmarshal(keyPair.Value, &keys)
			if err != nil {
				return err
			}

			logger.Debug("Updated Keys", "keys", keys, "path", path)

		OUTER_NEW:
			for _, key := range keys {
				watchersMut.RLock()
				for existing := range watchers {
					if existing == key {
						watchersMut.RUnlock()
						continue OUTER_NEW
					}
				}
				watchersMut.RUnlock()

				g.Go(newKeyWatcher(ctx, kv, key))
			}
		}
	})

	return g.Wait()
}

func newKeyWatcher(ctx context.Context, kv *consul.KV, key string) func() error {
	baseLogger.Trace("Creating new Key watcher", "key", key)
	return func() error {
		watcher := NewKeyWatcher(ctx, kv, key)
		watcher.CancelOnMissing = true
		go watcher.Watch()

		watchersMut.Lock()
		watchers[key] = watcher
		watchersMut.Unlock()

		defer func() {
			watchersMut.Lock()
			delete(watchers, key)
			watchersMut.Unlock()
		}()

		for {
			_, dataOK := <-watcher.Data()

			// Converge on change, even if the key disappeared
			convergeChan <- struct{}{}

			if !dataOK {
				// Channel closed (key probably deleted)
				break
			}
		}

		return nil
	}
}

// Runs the convergence routine based on triggers from KeyWatchers
// and an hourly timer.
//
// In brief:
//   1. Fetch all sites/, pki/, and revoke/ objects.
//   2. Handle revoke requests first.
//   3. Compare sites to pki, creating missing keys.
//   4. Loop through pki and check expiration, renew certs that still have site entries.
func converger(ctx context.Context, kv *consul.KV, prefix string, acmeClient *acme.Client, config *Config) error {
	logger := baseLogger.Named("converge")

	timer := time.NewTimer(time.Hour)
	defer timer.Stop()

	for {
		var (
			revokes []*RevokeConfig
			sites   []*SiteConfig
			certs   []*x509.Certificate
		)

		g, innerCtx := errgroup.WithContext(ctx)

		// Wait for a condition: the end of the context, a converge signal, or a timer pop
		select {
		case <-ctx.Done():
			logger.Trace("context closed")
			return nil
		case _, ok := <-convergeChan:
			logger.Trace("converge chan hit")
			if !ok {
				logger.Trace("converge chan closed")
				return nil
			}
			if !timer.Stop() {
				// See: https://golang.org/pkg/time/#Timer.Reset
				<-timer.C
			}
		case <-timer.C:
			logger.Trace("timer hit")
		}

		// Reset the timer after every convergence
		timer.Reset(time.Hour)

		logger.Debug("Fetching all data")

		g.Go(func() error {
			var err error
			revokes, err = getAllRevokes(innerCtx, kv, prefix, config)
			return err
		})
		g.Go(func() error {
			var err error
			sites, err = getAllSites(innerCtx, kv, prefix, config)
			return err
		})
		g.Go(func() error {
			var err error
			certs, err = getAllCerts(innerCtx, kv, prefix)
			return err
		})

		err := g.Wait()
		if err != nil {
			logger.Error("Unable to fetch data", "err", err)
			continue
		}

		logger.Debug("Data fetched", "revokes", len(revokes), "sites", len(sites), "certs", len(certs))

		for _, rev := range revokes {
			err = doRevoke(ctx, prefix, kv, acmeClient, rev)
			if err != nil {
				logger.Error("Unable to revoke cert", "err", err)
				continue
			}
		}

		if len(revokes) > 1 {
			if len(convergeChan) == 0 {
				convergeChan <- struct{}{}
			}

			logger.Debug("Restarting converge due to revokes")
			continue
		}

	SITES:
		for _, site := range sites {
			for _, cert := range certs {
				if site.FQDN == cert.Subject.CommonName {
					continue SITES
				}
			}

			// New Cert
			logger.Info("New cert", "fqdn", site.FQDN)
			err = doNewCert(ctx, prefix, kv, acmeClient, site)
			if err != nil {
				logger.Error("Unable to create new cert", "err", err)
				continue SITES
			}
		}

	CERTS:
		for _, cert := range certs {
			logger.Debug("Checking cert", "cert", cert.Subject)
			for _, site := range sites {
				if site.FQDN == cert.Subject.CommonName {
					innerLogger := logger.With("fqdn", site.FQDN)
					innerLogger.Trace("Matched Site", "site", site)

					renewDuration := time.Duration(site.Renew) * 24 * time.Hour

					if cert.NotAfter.Before(time.Now()) || time.Until(cert.NotAfter) <= renewDuration {
						innerLogger.Info("Cert needs renewal")
						err = doNewCert(ctx, prefix, kv, acmeClient, site)
						if err != nil {
							innerLogger.Error("Unable to renew cert", "err", err)
							continue CERTS
						}
					}

					innerLogger.Trace("No renewal needed")

					continue CERTS
				}
			}

			logger.Warn("Unmanaged cert in PKI", "fqdn", cert.Subject.CommonName)
		}
	}
}

func doNewCert(ctx context.Context, prefix string, kv *consul.KV, acmeClient *acme.Client, site *SiteConfig) error {
	logger := baseLogger.Named("doNewCert").With("fqdn", site.FQDN)

	crt, key, err := CreateACMECert(ctx, acmeClient, site)
	if err != nil {
		logger.Error("Unable to create new cert", "err", err)
		return err
	}

	err = storeCertAndKey(kv, prefix, site.FQDN, crt, key)
	if err != nil {
		logger.Error("Unable to store new cert", "err", err)
		return err
	}

	siteKey := fmt.Sprintf("%s/%s/%s", prefix, consulSitesPrefix, site.FQDN)
	err = setSiteConfig(ctx, kv, siteKey, site)
	if err != nil {
		logger.Error("Unable to store updated site key", "err", err)
		return err
	}

	return nil
}

func doRevoke(ctx context.Context, prefix string, kv *consul.KV, acmeClient *acme.Client, rev *RevokeConfig) error {
	logger := baseLogger.Named("doRevoke").With("fqdn", rev.FQDN)

	logger.Info("Revoking cert")
	err := acmeClient.RevokeCert(ctx, nil, rev.Cert.Raw, acme.CRLReasonUnspecified)
	if err != nil {
		return err
	}

	ops := consul.KVTxnOps{
		&consul.KVTxnOp{
			Verb: consul.KVDelete,
			Key:  fmt.Sprintf("%s/%s/%s", prefix, consulRevokePrefix, rev.FQDN),
		},
		&consul.KVTxnOp{
			Verb: consul.KVDelete,
			Key:  fmt.Sprintf("%s/%s/%s-key.pem", prefix, consulPKIPrefix, rev.FQDN),
		},
		&consul.KVTxnOp{
			Verb: consul.KVDelete,
			Key:  fmt.Sprintf("%s/%s/%s-cert.pem", prefix, consulPKIPrefix, rev.FQDN),
		},
	}

	if rev.Purge {
		dns, err := rev.GetProvider()
		if err != nil {
			return err
		}

		siteOp := &consul.KVTxnOp{
			Verb: consul.KVDelete,
			Key:  fmt.Sprintf("%s/%s/%s", prefix, consulSitesPrefix, rev.FQDN),
		}
		varOp := &consul.KVTxnOp{
			Verb: consul.KVDelete,
			Key:  fmt.Sprintf("%s/%s/%s", prefix, consulVarPrefix, rev.FQDN),
		}
		ops = append(ops, siteOp, varOp)

		for _, id := range rev.DNSProviderIDs {
			logger.Info("Deleting DNS record", "id", id)
			err = dns.Delete(id)
			if err != nil {
				return err
			}
		}

		for _, url := range rev.ACMEAuthorizationURLs {
			logger.Info("Revoking ACME Authorization", "url", url)
			err = acmeClient.RevokeAuthorization(ctx, url)
			if err != nil {
				return err
			}
		}
	}

	q := new(consul.QueryOptions)
	q = q.WithContext(ctx)

	ok, resp, _, err := kv.Txn(ops, q)
	if err != nil {
		return err
	}

	if !ok {
		return fmt.Errorf("Transaction rolled back: %v", resp.Errors)
	}

	return nil
}
