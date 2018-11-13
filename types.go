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
)

// Config is the main config struct, encoding the data from
// the {PREFIX}/conf key in Consul.
type Config struct {
	Email        string           `json:"email"`
	Ident        CSRIdent         `json:"ident"`
	Renew        int              `json:"renew"`
	DNSProviders *ProviderFactory `json:"dns_config"`
}

func (c *Config) String() string {
	return fmt.Sprintf("Config{Email:%s Ident:%s, Renew:%d, DNSProviders:%s}", c.Email, c.Ident, c.Renew, c.DNSProviders)
}

// CSRIdent encodes the data in the `ident` key in the Config struct.
type CSRIdent struct {
	Country            []string `json:"country"`
	Province           []string `json:"province"`
	Locality           []string `json:"locality"`
	Organization       []string `json:"organization"`
	OrganizationalUnit []string `json:"organizational_unit"`
}

// SiteConfig extends the main config struct for use in site-specific configs.
type SiteConfig struct {
	Config
	ExtraNames  []string `json:"extra_names"`
	DNSProvider string   `json:"dns_provider"`
	FQDN        string

	// Used internally. The provider-specific ID for the challenge record.
	DNSProviderID string `json:"dns_provider_id"`
}

// Auth stores the ACME registration data.
type Auth struct {
	Email string `json:"email"`
	URI   string `json:"uri"`

	// PrivateKey in PEM-encoded format
	PrivateKey string `json:"private_key"`
}

// TXTRecord is a generalization of a DNS providers' TXT record.
type TXTRecord interface {
	// ID should return a string representation of the provider's internal record ID.
	ID() string

	// Name should return the name of the TXT record (not the FQDN).
	Name() string

	// Text should return the value of the TXT record.
	Text() string
}

// DNSProvider is an interface the concrete DNS providers must implement
type DNSProvider interface {
	// Create accepts a TXTRecord "prototype" and creates that record, returning the ID.
	Create(TXTRecord) (string, error)

	// Delete accepts the record ID and deletes that record.
	Delete(string) error

	// Get fetches the TXT record with the given ID.
	Get(string) (TXTRecord, error)
}
