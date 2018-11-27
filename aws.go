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
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/external"
	"github.com/aws/aws-sdk-go-v2/service/route53"
)

const (
	route53SearchMaxItems = "50"
)

// AWSConfig encodes the configuration for the AWS Route53 DNS Provider.
type AWSConfig struct {
	AccessKeyID     string `json:"access_key_id"`
	SecretAccessKey string `json:"secret_access_key"`
	DomainID        string `json:"domain_id"`
}

// AWSProvider is the AWS Route53 DNS Provider.
type AWSProvider struct {
	client   *route53.Route53
	domainID string
}

// NewAWSProvider returns a new AWSProvider instance
func NewAWSProvider(config *AWSConfig) (*AWSProvider, error) {
	awsConfig, err := external.LoadDefaultAWSConfig(
		external.WithCredentialsValue(aws.Credentials{
			AccessKeyID:     config.AccessKeyID,
			SecretAccessKey: config.SecretAccessKey,
		}),
	)

	if err != nil {
		return nil, err
	}

	client := route53.New(awsConfig)

	return &AWSProvider{
		client:   client,
		domainID: config.DomainID,
	}, nil
}

// Get implements the DNSProvider interface Get method.
func (a *AWSProvider) Get(id string) (TXTRecord, error) {
	logger := baseLogger.Named("AWSProvider").Named("Get")

	var out *GenericTXTRecord

	input := &route53.ListResourceRecordSetsInput{
		HostedZoneId: aws.String(a.domainID),
		MaxItems:     aws.String(route53SearchMaxItems),
	}

	for {
		logger.Trace("Fetching page", "input", input)

		req := a.client.ListResourceRecordSetsRequest(input)
		resp, err := req.Send()
		if err != nil {
			return nil, err
		}

		logger.Trace("Page", "resp", resp)

		for _, rrSet := range resp.ResourceRecordSets {
			if aws.StringValue(rrSet.Name) == id {
				logger.Trace("found", "rrSet", rrSet)

				if len(rrSet.ResourceRecords) == 0 {
					return nil, fmt.Errorf("Found record, but value empty: %s", rrSet)
				}

				out = &GenericTXTRecord{
					name: id,
					text: aws.StringValue(rrSet.ResourceRecords[0].Value),
				}
				break
			}
		}

		if out != nil {
			break
		}

		if *resp.IsTruncated {
			input.StartRecordName = resp.NextRecordName
			input.StartRecordType = resp.NextRecordType
			continue
		}

		break
	}

	if out == nil {
		logger.Trace("Not found", "id", id)
		return nil, nil
	}

	return out, nil
}

// Create implements the DNSProvider interface Create method.
func (a *AWSProvider) Create(proto TXTRecord) (string, error) {
	logger := baseLogger.Named("AWSProvider").Named("Create")

	input := &route53.ChangeResourceRecordSetsInput{
		HostedZoneId: aws.String(a.domainID),
		ChangeBatch: &route53.ChangeBatch{
			Changes: []route53.Change{
				{
					Action: route53.ChangeActionUpsert,
					ResourceRecordSet: &route53.ResourceRecordSet{
						Name: aws.String(proto.Name()),
						Type: route53.RRTypeTxt,
						TTL:  aws.Int64(acmeChallengeTTL),
						ResourceRecords: []route53.ResourceRecord{
							{Value: aws.String(fmt.Sprintf(`"%s"`, proto.Text()))},
						},
					},
				},
			},
		},
	}

	logger.Trace("Creating record", "input", input)

	req := a.client.ChangeResourceRecordSetsRequest(input)
	resp, err := req.Send()
	if err != nil {
		return "", err
	}

	logger.Trace("AWS response", "response", resp)

	logger.Debug("Waiting for Route53 propagation")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	err = a.client.WaitUntilResourceRecordSetsChangedWithContext(ctx, &route53.GetChangeInput{Id: resp.ChangeInfo.Id})
	if err != nil {
		logger.Error("Error while waiting for Route53, continuing anyway", "err", err)
	}

	id := proto.Name()
	if !strings.HasSuffix(id, ".") {
		id = id + "."
	}

	return id, nil
}

// Delete implements the DNSProvider interface Delete method.
func (a *AWSProvider) Delete(id string) error {
	logger := baseLogger.Named("AWSProvider").Named("Delete")

	record, err := a.Get(id)
	if err != nil {
		return err
	}

	if record == nil {
		return nil
	}

	logger.Trace("Found record", "record", fmt.Sprintf("%#v", record))

	input := &route53.ChangeResourceRecordSetsInput{
		HostedZoneId: aws.String(a.domainID),
		ChangeBatch: &route53.ChangeBatch{
			Changes: []route53.Change{
				{
					Action: route53.ChangeActionDelete,
					ResourceRecordSet: &route53.ResourceRecordSet{
						Name: aws.String(id),
						Type: route53.RRTypeTxt,
						ResourceRecords: []route53.ResourceRecord{
							{Value: aws.String(fmt.Sprintf(`"%s"`, record.Text()))},
						},
					},
				},
			},
		},
	}

	logger.Trace("Deleting record", "input", input)

	req := a.client.ChangeResourceRecordSetsRequest(input)
	resp, err := req.Send()
	logger.Trace("AWS response", "response", resp)

	return err
}
