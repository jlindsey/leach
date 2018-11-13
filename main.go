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
	"encoding/json"
	"fmt"
	"os"
	"strings"

	consul "github.com/hashicorp/consul/api"
	"github.com/hashicorp/go-hclog"
	"github.com/imdario/mergo"
	"golang.org/x/crypto/acme"
	"gopkg.in/urfave/cli.v1"
)

const (
	defaultConsulAddr   = "127.0.0.1:8500"
	defaultConsulPrefix = "leach"
	defaultLogLevel     = "INFO"

	acmeStagingURL = "https://acme-staging.api.letsencrypt.org/directory"

	consulConfigKey    = "config"
	consulAuthKey      = "auth"
	consulSitesPrefix  = "sites"
	consulPKIPrefix    = "pki"
	consulRevokePrefix = "revoke"
)

var (
	// Version is the version of the app, provided by ldflags when building for release.
	Version = "0.0.0"
	// GitSHA is the commit of the build.
	GitSHA = ""

	baseLogger hclog.Logger
)

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
		cli.BoolFlag{
			Name:   "staging, s",
			Usage:  "Use LetsEncrypt staging environment instead of production",
			EnvVar: "LE_STAGING",
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
	config, err := getConfig(kv, prefix)
	if err != nil {
		return err
	}
	baseLogger.Trace("Got config", "config", config)

	auth, err := getAuth(kv, prefix)
	if err != nil {
		return err
	}
	if auth == nil {
		// New Login
		auth = &Auth{Email: config.Email}
	}

	directoryURL := acme.LetsEncryptURL
	if c.Bool("staging") {
		directoryURL = acmeStagingURL
	}
	baseLogger.Debug("Using directory", "url", directoryURL)

	acmeClient := &acme.Client{DirectoryURL: directoryURL}
	err = DoAuth(context.TODO(), acmeClient, auth)
	if err != nil {
		return err
	}

	err = setAuth(kv, prefix, auth)
	if err != nil {
		return err
	}

	return watchSites(context.TODO(), prefix, kv, acmeClient, config)
}

func watchSites(ctx context.Context, prefix string, kv *consul.KV, acmeClient *acme.Client, config *Config) error {
	logger := baseLogger.Named("watchSites")
	sitesPath := fmt.Sprintf("%s/%s/", prefix, consulSitesPrefix)
	siteKeysWatcher := NewKeyWatcher(ctx, kv, sitesPath)
	go siteKeysWatcher.Watch()

	for {
		siteKeysBytes := <-siteKeysWatcher.Data
		siteKeys := make([]string, 0)
		err := json.Unmarshal(siteKeysBytes, &siteKeys)
		if err != nil {
			return err
		}

		logger.Debug("Updated sites", "keys", siteKeys)

		for _, siteKey := range siteKeys {
			siteConfig, err := getSiteConfig(kv, siteKey, config)
			if err != nil {
				return err
			}

		}
	}
}

func getSiteConfig(kv *consul.KV, key string, config *Config) (*SiteConfig, error) {
	split := strings.Split(key, "/")
	fqdn := split[len(split)-1]

	pair, _, err := kv.Get(key, nil)
	if err != nil {
		return nil, err
	}

	if pair == nil {
		return nil, fmt.Errorf("No site config found at %s", key)
	}

	siteConfig := new(SiteConfig)
	if err = json.Unmarshal(pair.Value, siteConfig); err != nil {
		return nil, err
	}

	siteConfig.FQDN = fqdn

	if err = mergo.Merge(siteConfig, config); err != nil {
		return nil, err
	}

	return siteConfig, nil
}

func getConfig(kv *consul.KV, prefix string) (*Config, error) {
	path := fmt.Sprintf("%s/%s", prefix, consulConfigKey)
	pair, _, err := kv.Get(path, nil)
	if err != nil {
		return nil, err
	}

	if pair == nil {
		return nil, fmt.Errorf("No config found at %s", path)
	}

	config := new(Config)
	if err = json.Unmarshal(pair.Value, config); err != nil {
		return nil, err
	}

	return config, nil
}

func getAuth(kv *consul.KV, prefix string) (*Auth, error) {
	path := fmt.Sprintf("%s/%s", prefix, consulAuthKey)
	pair, _, err := kv.Get(path, nil)
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

func setAuth(kv *consul.KV, prefix string, auth *Auth) error {
	path := fmt.Sprintf("%s/%s", prefix, consulAuthKey)

	encoded, err := json.Marshal(auth)
	if err != nil {
		return err
	}

	data := &consul.KVPair{
		Key:   path,
		Value: encoded,
	}

	if _, err = kv.Put(data, nil); err != nil {
		return err
	}

	return nil
}
