package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
)

const (
	doViewSep = `<<<<++++>>>>`
)

type ibTXTRecord struct {
	Ref     string `json:"_ref"`
	DNSName string `json:"dns_name"`
	Data    string `json:"text"`
}

func (r *ibTXTRecord) ID() string {
	return r.Ref
}

func (r *ibTXTRecord) Name() string {
	return r.DNSName
}

func (r *ibTXTRecord) Text() string {
	return r.Data
}

// IBConfig encodes the configuration for the Infoblox DNS Provider.
type IBConfig struct {
	BaseURL  string   `json:"url"`
	Username string   `json:"username"`
	Password string   `json:"password"`
	Views    []string `json:"views"`
}

// IBProvider is the Infoblox DNS Provider.
type IBProvider struct {
	client *http.Client
	config *IBConfig
}

// NewIBProvider creates a new Infoblox DNS Provider from the provided config.
func NewIBProvider(config *IBConfig) *IBProvider {
	return &IBProvider{
		config: config,
		client: &http.Client{},
	}
}

// Get implements the DNSProvider interface Get method.
func (d *IBProvider) Get(id string) (TXTRecord, error) {
	split := strings.Split(id, doViewSep)
	uri := fmt.Sprintf("%s/%s", d.config.BaseURL, split[0])

	req, err := http.NewRequest("GET", uri, nil)
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(d.config.Username, d.config.Password)
	q := req.URL.Query()
	q.Set("_return_fields+", "dns_name")
	req.URL.RawQuery = q.Encode()

	resp, err := d.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("bad response from infoblox: %s", respBody)
	}

	out := new(ibTXTRecord)
	err = json.Unmarshal(respBody, out)
	if err != nil {
		return nil, err
	}

	return out, nil
}

// Create implements the DNSProvider interface Create method.
func (d *IBProvider) Create(proto TXTRecord) (string, error) {
	out := make([]string, len(d.config.Views))
	for i, view := range d.config.Views {
		uri := fmt.Sprintf("%s/record:txt", d.config.BaseURL)

		reqBody := map[string]interface{}{
			"name": proto.Name(),
			"text": proto.Text(),
			"view": view,
			"ttl":  acmeChallengeTTL,
		}

		body, err := json.Marshal(reqBody)
		if err != nil {
			return "", err
		}

		req, err := http.NewRequest("POST", uri, bytes.NewBuffer(body))
		if err != nil {
			return "", err
		}
		req.SetBasicAuth(d.config.Username, d.config.Password)

		resp, err := d.client.Do(req)
		if err != nil {
			return "", err
		}

		respBody, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return "", err
		}

		if resp.StatusCode != http.StatusCreated {
			return "", fmt.Errorf("bad response from infoblox: %s", respBody)
		}

		out[i] = strings.Trim(string(respBody), `"`)
	}

	return strings.Join(out, doViewSep), nil
}

// Delete implements the DNSProvider interface Delete method.
func (d *IBProvider) Delete(joinedIDs string) error {
	ids := strings.Split(joinedIDs, doViewSep)
	for _, id := range ids {
		uri := fmt.Sprintf("%s/%s", d.config.BaseURL, id)

		req, err := http.NewRequest("DELETE", uri, nil)
		if err != nil {
			return err
		}
		req.SetBasicAuth(d.config.Username, d.config.Password)

		resp, err := d.client.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()

		respBody, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return err
		}

		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("bad response from infoblox: %s", respBody)
		}
	}

	return nil
}
