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
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strconv"
)

var doAPIEndpoint = "https://api.digitalocean.com/v2/domains"

type doTXTRecord struct {
	Ref        int    `json:"id"`
	DomainName string `json:"name"`
	Data       string `json:"data"`
}

func (r *doTXTRecord) ID() string {
	return strconv.Itoa(r.Ref)
}

func (r *doTXTRecord) Name() string {
	return r.DomainName
}

func (r *doTXTRecord) Text() string {
	return r.Data
}

// DOConfig encodes the configuration for the DigitalOcean DNS provider.
type DOConfig struct {
	Token string `json:"token"`
	Zone  string `json:"zone"`
}

// DOProvider is the concrete implementation of DNSProvider for DigitalOcean.
type DOProvider struct {
	client *http.Client
	config *DOConfig
}

func (d *DOProvider) String() string {
	return fmt.Sprintf("DOProvider{Zone:%s}", d.config.Zone)
}

// NewDOProvider takes a config and returns a new DOProvider.
func NewDOProvider(config *DOConfig) *DOProvider {
	return &DOProvider{
		config: config,
		client: &http.Client{},
	}
}

// Get implements the DNSProvider interface Get method.
func (d *DOProvider) Get(id string) (TXTRecord, error) {
	return nil, nil
}

// Create implements the DNSProvider interface Create method.
func (d *DOProvider) Create(proto TXTRecord) (string, error) {
	logger := baseLogger.Named("DOProvider").Named("Create")

	dnsReqBody := map[string]string{
		"type": "TXT",
		"name": proto.Name(),
		"ttl":  strconv.Itoa(acmeChallengeTTL),
		"data": proto.Text(),
	}

	logger.Debug("DNS record to create", "req", dnsReqBody)

	body, err := json.Marshal(dnsReqBody)
	if err != nil {
		return "", err
	}

	uri := fmt.Sprintf("%s/%s/records", doAPIEndpoint, d.config.Zone)
	logger.Trace("POST", "uri", uri)

	req, err := http.NewRequest("POST", uri, bytes.NewBuffer(body))
	if err != nil {
		return "", err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", d.config.Token))

	resp, err := d.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	respBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	if resp.StatusCode != 201 {
		return "", fmt.Errorf("bad response from DO API: %s", respBody)
	}

	out := struct {
		Record doTXTRecord `json:"domain_record"`
	}{}

	err = json.Unmarshal(respBody, &out)
	if err != nil {
		return "", err
	}

	return out.Record.ID(), nil
}

// Delete implements the DNSProvider interface Delete method.
func (d *DOProvider) Delete(id string) error {
	return nil
}
