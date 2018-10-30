package main

import (
	"context"
	"fmt"
	"os"
	"time"

	consul "github.com/hashicorp/consul/api"
	"golang.org/x/crypto/acme"
	"gopkg.in/urfave/cli.v1"
)

var (
	// Version is the version of the app, provided by ldflags when building for release.
	Version = "0.0.0"
	// GitSHA is the commit of the build.
	GitSHA = ""
)

const (
	keyBits         = 2048
	certDuration    = 90 * 24 * time.Hour // LE only offers 90-day certs
	configKey       = "base_ident"
	authKey         = "auth"
	sitesKey        = "sites"
	pkiKey          = "pki"
	stagingEndpoint = "https://acme-staging.api.letsencrypt.org/directory"
)

type contextStoreKey int

const (
	ctxConsulClient contextStoreKey = iota
	ctxConsulPrefix
	ctxLetsEncryptEndpoint
)

type csrIdent struct {
	Country            []string `json:"country"`
	Province           []string `json:"province"`
	Locality           []string `json:"locality"`
	Organization       []string `json:"organization"`
	OrganizationalUnit []string `json:"organizational_unit"`
}

func main() {
	app := cli.NewApp()
	app.Usage = "Automated LetsEncrypt Consul integration"
	app.Version = fmt.Sprintf("%s (%s)", Version, GitSHA)
	app.HideHelp = true
	app.UsageText = "porter [options]"
	app.Before = cli.BeforeFunc(getConsulClient)
	app.Action = run
	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:   "consul-addr, a",
			Value:  "127.0.0.1:8500",
			Usage:  "Connect to Consul running at `ADDR`",
			EnvVar: "CONSUL_ADDR",
		},
		cli.StringFlag{
			Name:   "consul-prefix, c",
			Value:  "porter",
			Usage:  "Consul KV store `PREFIX` for configuration and storage",
			EnvVar: "CONSUL_PREFIX",
		},
		cli.BoolFlag{
			Name:   "staging, s",
			Usage:  "Use LetsEncrypt staging environment instead of production",
			EnvVar: "LE_STAGING",
		},
		cli.StringFlag{
			Name:   "infoblox-user, u",
			Usage:  "Use `USER` to authenticate with the Infoblox API",
			EnvVar: "INFOBLOX_USER",
		},
		cli.StringFlag{
			Name:   "infoblox-pass, p",
			Usage:  "Use `PASS` to authenticate with the Infoblox API",
			EnvVar: "INFOBLOX_PASS",
		},
		cli.BoolFlag{
			Name:  "help, h",
			Usage: "show help",
		},
	}

	err := app.Run(os.Args)
	if err != nil {
		panic(err)
	}
}

func run(c *cli.Context) error {
	if c.Bool("help") {
		cli.ShowAppHelpAndExit(c, 0)
		return nil
	}

	consulClient := c.App.Metadata["consul"].(*consul.Client)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	ctx = context.WithValue(ctx, ctxConsulClient, consulClient)
	ctx = context.WithValue(ctx, ctxConsulPrefix, c.String("consul-prefix"))
	uri := acme.LetsEncryptURL
	if c.Bool("staging") {
		uri = stagingEndpoint
	}
	ctx = context.WithValue(ctx, ctxLetsEncryptEndpoint, uri)

	_, err := getAcmeClient(ctx)
	if err != nil {
		cancel()
		return err
	}

	cancel()

	return nil
}

func getConsulClient(c *cli.Context) error {
	client, err := consul.NewClient(&consul.Config{
		Address: c.String("consul-addr"),
	})

	if err != nil {
		return err
	}

	c.App.Metadata["consul"] = client
	return nil
}

// func do(c *cli.Context) error {
// 	keyBytes, err := ioutil.ReadFile("key.pem")
// 	if err != nil {
// 		panic(err)
// 	}

// 	block, _ := pem.Decode(keyBytes)
// 	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
// 	if err != nil {
// 		panic(err)
// 	}

// 	client := &acme.Client{Key: key}

// 	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
// 	defer cancel()
// 	acct, err := client.GetReg(ctx, "")
// 	if err != nil {
// 		panic(err)
// 	}

// 	fmt.Printf("Account URI: %s\n", acct.URI)
// 	fmt.Printf("Account Authz: %s\n", acct.Authz)

// 	auth, err := client.Authorize(context.Background(), "ui.jlindsey.me")
// 	if err != nil {
// 		panic(err)
// 	}

// 	spew.Dump(auth)

// 	if auth.Status != "valid" {
// 		var dnsChallenge *acme.Challenge
// 		for _, chal := range auth.Challenges {
// 			if chal.Type == "dns-01" {
// 				dnsChallenge = chal
// 				break
// 			}
// 		}

// 		if dnsChallenge == nil {
// 			panic("no dns challenge")
// 		}

// 		dnsChallenge, err = client.Accept(context.Background(), dnsChallenge)
// 		if err != nil {
// 			panic(err)
// 		}

// 		s, err := client.DNS01ChallengeRecord(dnsChallenge.Token)
// 		if err != nil {
// 			panic(err)
// 		}

// 		spew.Dump(s)

// 		dnsReqBody := map[string]string{
// 			"type": "TXT",
// 			"name": "_acme-challenge.ui",
// 			"ttl":  "300",
// 			"data": s,
// 		}
// 		body, err := json.Marshal(dnsReqBody)
// 		if err != nil {
// 			panic(err)
// 		}

// 		httpClient := &http.Client{}
// 		req, err := http.NewRequest("POST", fmt.Sprintf(doDomainAPIURL, "jlindsey.me"), bytes.NewBuffer(body))
// 		if err != nil {
// 			panic(err)
// 		}
// 		req.Header.Set("Content-Type", "application/json")
// 		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

// 		resp, err := httpClient.Do(req)
// 		if err != nil {
// 			panic(err)
// 		}
// 		defer resp.Body.Close()

// 		respBody, err := ioutil.ReadAll(resp.Body)
// 		if err != nil {
// 			panic(err)
// 		}

// 		if resp.StatusCode != 201 {
// 			panic(string(respBody))
// 		}
// 	}

// 	goodAuth, err := client.WaitAuthorization(context.Background(), auth.URI)
// 	if err != nil {
// 		panic(err)
// 	}

// 	spew.Dump(goodAuth)

// 	req := &x509.CertificateRequest{
// 		SignatureAlgorithm: x509.SHA256WithRSA,
// 		Subject: pkix.Name{
// 			Country:            []string{"US"},
// 			Province:           []string{"Virginia"},
// 			Locality:           []string{"Arlington"},
// 			Organization:       []string{"jlindsey.me"},
// 			OrganizationalUnit: []string{"Me"},
// 			CommonName:         "ui.jlindsey.me",
// 		},
// 	}

// 	csr, err := x509.CreateCertificateRequest(rand.Reader, req, key)
// 	if err != nil {
// 		panic(err)
// 	}

// 	crt, crtURL, err := client.CreateCert(context.Background(), csr, 24*30*time.Hour, true)
// 	if err != nil {
// 		panic(err)
// 	}

// 	fmt.Printf("Cert URL: %s\n", crtURL)

// 	crtBlock := &pem.Block{
// 		Bytes: crt[0],
// 		Type:  "CERTIFICATE",
// 	}

// 	err = ioutil.WriteFile("ui.jlindsey.me.crt", pem.EncodeToMemory(crtBlock), 0644)
// 	if err != nil {
// 		panic(err)
// 	}

// 	chainBlock := &pem.Block{
// 		Bytes: make([]byte, 0),
// 		Type:  "CERTIFICATE",
// 	}

// 	for _, cert := range crt[1:] {
// 		for _, b := range cert {
// 			chainBlock.Bytes = append(chainBlock.Bytes, b)
// 		}
// 	}

// 	err = ioutil.WriteFile("ui.jlindsey.me.chain", pem.EncodeToMemory(chainBlock), 0644)
// 	return nil
// }
