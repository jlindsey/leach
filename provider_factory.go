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
	"encoding/json"
	"fmt"
)

const (
	defaultName = "default"
	providerKey = "provider"

	doProviderName  = "digitalocean"
	ibProviderName  = "infoblox"
	awsProviderName = "aws"
)

type providerEnvelope struct {
	ProviderName string `json:"provider"`
}

// ProviderFactory parses the JSON configs for DNS providers and
// loads them for later.
type ProviderFactory struct {
	providers map[string]DNSProvider
}

func (f *ProviderFactory) String() string {
	return fmt.Sprintf("ProviderFactory{Providers:%s}", f.providers)
}

// UnmarshalJSON implements the JSON Unmarshaller interface.
func (f *ProviderFactory) UnmarshalJSON(b []byte) error {
	rawConfigs := make(map[string]json.RawMessage)
	err := json.Unmarshal(b, &rawConfigs)
	if err != nil {
		return err
	}

	_, ok := rawConfigs[defaultName]
	if !ok {
		return fmt.Errorf("Must have a default DNS config")
	}

	f.providers = make(map[string]DNSProvider, len(rawConfigs))

	for name, raw := range rawConfigs {
		pe := new(providerEnvelope)
		err = json.Unmarshal(raw, pe)
		if err != nil {
			return err
		}

		var provider DNSProvider

		switch pe.ProviderName {
		case doProviderName:
			doConfig := new(DOConfig)
			err = json.Unmarshal(raw, doConfig)
			if err != nil {
				return err
			}

			provider = NewDOProvider(doConfig)
		case ibProviderName:
			ibConfig := new(IBConfig)
			err = json.Unmarshal(raw, ibConfig)
			if err != nil {
				return err
			}

			provider = NewIBProvider(ibConfig)
		case awsProviderName:
			awsConfig := new(AWSConfig)
			err = json.Unmarshal(raw, awsConfig)
			if err != nil {
				return nil
			}

			provider, err = NewAWSProvider(awsConfig)
			if err != nil {
				return err
			}
		default:
			return fmt.Errorf("Unsupported or missing provider for `%s`: %s", name, pe.ProviderName)
		}

		f.providers[name] = provider
	}

	return nil
}

// Get returns the provider with the given config name, or an error if it does not exist.
func (f *ProviderFactory) Get(name string) (DNSProvider, error) {
	provider, ok := f.providers[name]
	if !ok {
		return nil, fmt.Errorf("No provider named %s", name)
	}

	return provider, nil
}

// Default returns the default provider, which will always exist.
func (f *ProviderFactory) Default() DNSProvider {
	provider, _ := f.Get(defaultName)
	return provider
}
