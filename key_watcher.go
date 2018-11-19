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
	"context"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"strings"

	consul "github.com/hashicorp/consul/api"
	"github.com/hashicorp/go-hclog"
)

// KeyWatcher manages long-polling a Consul KV store endpoint. It maintains an
// internal checksum of the watched data and will only write to the Data chan
// when the data actually changes to get around Consul raft index global updates.
type KeyWatcher struct {
	client   *consul.KV
	index    uint64
	checksum []byte
	path     string
	ctx      context.Context
	cancel   context.CancelFunc
	logger   hclog.Logger
	data     chan *consul.KVPair

	// CancelOnMissing instructs the watcher to cancel itself if the key is or
	// becomes missing.
	CancelOnMissing bool
}

// NewKeyWatcher creates a new KeyWatcher. The passed-in context will be used for
// global coordination - Watch() will exit and  Close() will be called automatically
// when the parent Context is canceled.
//
// If the provided path ends in a `/`, the watcher will return a list of keys with
// that prefix instead of a value (KV.GetKeys() vs KV.Get()).
func NewKeyWatcher(ctx context.Context, kv *consul.KV, path string) *KeyWatcher {
	dataChan := make(chan *consul.KVPair)
	innerCtx, cancel := context.WithCancel(ctx)

	return &KeyWatcher{
		client: kv,
		path:   path,
		ctx:    innerCtx,
		cancel: cancel,
		data:   dataChan,
		logger: baseLogger.Named("KeyWatcher").With("path", path),
	}
}

// Data returns the chan into which updates are written.
func (k *KeyWatcher) Data() chan *consul.KVPair {
	return k.data
}

// Close implements the Closer interface. Stops the watcher routine and closes the
// Data chan.
func (k *KeyWatcher) Close() error {
	k.logger.Trace("Closing")

	k.cancel()
	close(k.data)

	return nil
}

// Watch starts the watcher. Should be run in a goroutine, preferably with an errgroup.
func (k *KeyWatcher) Watch() error {
	logger := k.logger.Named("Watch").With("index", k.index)
	logger.Trace("Starting")

	for {
		select {
		case <-k.ctx.Done():
			logger.Trace("Context canceled")
			return k.Close()
		default:
		}

		opts := &consul.QueryOptions{
			WaitIndex: k.index,
		}

		opts = opts.WithContext(k.ctx)

		var (
			pair *consul.KVPair
			keys []string
			meta *consul.QueryMeta
			err  error
		)

		if strings.HasSuffix(k.path, "/") {
			var rawKeys []string
			rawKeys, meta, err = k.client.Keys(k.path, "/", opts)
			for _, key := range rawKeys {
				if key == k.path {
					continue
				}

				keys = append(keys, key)
			}
		} else {
			pair, meta, err = k.client.Get(k.path, opts)
		}

		if err != nil {
			if strings.Contains(err.Error(), "context canceled") {
				// TODO: is there a better way to detect this?
				continue
			}
			return err
		}

		k.index = meta.LastIndex

		if pair == nil && keys == nil {
			if k.CancelOnMissing {
				k.logger.Debug("Key disappeared, canceling")
				k.cancel()
			}

			continue
		}

		var val []byte
		if pair != nil {
			val = make([]byte, len(pair.Value))
			copy(val, pair.Value)
		} else {
			val, err = json.Marshal(keys)
			if err != nil {
				return err
			}
		}

		h := md5.New()
		h.Write(val)
		b := h.Sum(nil)
		checksum := make([]byte, hex.EncodedLen(len(b)))
		hex.Encode(checksum, b)

		if bytes.Equal(checksum, k.checksum) {
			logger.Trace("Ignoring change", "oldCheck", string(k.checksum), "newCheck", string(checksum))
			continue
		}

		k.checksum = checksum

		k.data <- &consul.KVPair{
			Key:   k.path,
			Value: val,
		}
	}
}
