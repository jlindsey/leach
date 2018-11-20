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
	"crypto/x509"
	"fmt"
	"sync"
)

// Config is the main config struct, encoding the data from
// the {PREFIX}/conf key in Consul.
type Config struct {
	Email        string           `json:"email,omitempty"`
	Ident        *CSRIdent        `json:"ident,omitempty"`
	Renew        int              `json:"renew,omitempty"`
	DNSProviders *ProviderFactory `json:"dns_config,omitempty"`
}

func (c *Config) String() string {
	return fmt.Sprintf("Config{Email:%s Ident:%s, Renew:%d, DNSProviders:%s}", c.Email, c.Ident, c.Renew, c.DNSProviders)
}

// CSRIdent encodes the data in the `ident` key in the Config struct.
type CSRIdent struct {
	Country            []string `json:"country,omitempty"`
	Province           []string `json:"province,omitempty"`
	Locality           []string `json:"locality,omitempty"`
	Organization       []string `json:"organization,omitempty"`
	OrganizationalUnit []string `json:"organizational_unit,omitempty"`
}

// SiteConfig extends the main config struct for use in site-specific configs.
type SiteConfig struct {
	Config             `json:"-"`
	SiteConfigInternal `json:"-"`
	ExtraNames         []string `json:"extra_names,omitempty"`
	ProviderName       string   `json:"dns_provider,omitempty"`
	FQDN               string   `json:"-"`
}

// RevokeConfig is the configuration for the revoke/ path.
type RevokeConfig struct {
	*SiteConfig `json:"-"`
	Cert        *x509.Certificate `json:"-"`
	Purge       bool              `json:"purge"`
}

// SiteConfigInternal contains the set of internal-only SiteConfig values, stored
// separately from the main SiteConfig.
type SiteConfigInternal struct {
	mut *sync.Mutex

	// Used internally. The provider-specific IDs for the challenge records.
	DNSProviderIDs map[string]string `json:"dns_provider_ids,omitempty"`

	// Used internally. The ACME identifier URL(s) for the domain(s) authorization approval.
	ACMEAuthorizationURLs map[string]string `json:"acme_authorization_urls,omitempty"`

	// Used internally. The ACME identifier URL for re-downloading the certificate.
	ACMEDownloadURL string `json:"acme_download_url,omitempty"`
}

// AddDNSID is a thread-safe append to DNS IDs map
func (s *SiteConfigInternal) AddDNSID(domain, id string) {
	s.mut.Lock()
	defer s.mut.Unlock()

	s.DNSProviderIDs[domain] = id
}

// RemoveDNSID is a thread-safe delete from the DNS IDs map
func (s *SiteConfigInternal) RemoveDNSID(domain string) {
	s.mut.Lock()
	defer s.mut.Unlock()

	delete(s.DNSProviderIDs, domain)
}

// AddAuthorizationURL is a thread-safe append to the Authorization URLs map
func (s *SiteConfigInternal) AddAuthorizationURL(domain, url string) {
	s.mut.Lock()
	defer s.mut.Unlock()

	s.ACMEAuthorizationURLs[domain] = url
}

// RemoveAuthorizationURL is a thread-safe delete from the Authorization URLs map
func (s *SiteConfigInternal) RemoveAuthorizationURL(domain string) {
	s.mut.Lock()
	defer s.mut.Unlock()

	delete(s.ACMEAuthorizationURLs, domain)
}

// GetProvider returns the DNSProvider for this site
func (c *SiteConfig) GetProvider() (DNSProvider, error) {
	if c.ProviderName == "" {
		return c.DNSProviders.Default(), nil
	}

	return c.DNSProviders.Get(c.ProviderName)
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

	// Name should return the FQDN of the TXT record.
	Name() string

	// Text should return the value of the TXT record.
	Text() string
}

// GenericTXTRecord is a type that implements the TXTRecord interface that can be used to
// make generalized Create() calls into DNSProvider.
type GenericTXTRecord struct {
	name, text string
}

// ID implements TXTRecord.ID
func (t *GenericTXTRecord) ID() string {
	return ""
}

// Name implements TXTRecord.Name
func (t *GenericTXTRecord) Name() string {
	return t.name
}

// Text implements TXTRecord.Text
func (t *GenericTXTRecord) Text() string {
	return t.text
}

// DNSProvider is an interface the concrete DNS providers must implement
type DNSProvider interface {
	// Create accepts a TXTRecord "prototype" and creates that record, returning the ID.
	Create(TXTRecord) (string, error)

	// Delete accepts the record ID and deletes that record.
	Delete(string) error

	// Get fetches the TXT record with the given ID. If the record does not exist, it's acceptable
	// to return (nil, nil) from this method, and the authorization routine will make a new one.
	Get(string) (TXTRecord, error)
}
