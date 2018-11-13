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
	"fmt"
	"net/http"
)

var doAPIEndpoint = "https://api.digitalocean.com/v2/domains"

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
	return "", nil
}

// Delete implements the DNSProvider interface Delete method.
func (d *DOProvider) Delete(id string) error {
	return nil
}
