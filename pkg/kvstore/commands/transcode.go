// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package commands

import (
	"encoding/json"
	"fmt"
	"strings"

	mcsapitypes "github.com/cilium/cilium/pkg/clustermesh/mcsapi/types"
	clustermeshstore "github.com/cilium/cilium/pkg/clustermesh/store"
	"github.com/cilium/cilium/pkg/clustermesh/types/endpointslice"
	identitycache "github.com/cilium/cilium/pkg/identity/cache"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/kvstore/store"
	nodestore "github.com/cilium/cilium/pkg/node/store"
)

type transcodableJSON interface {
	store.Key
	json.Marshaler
	json.Unmarshaler
}

type prefixTranscodableJSONInfo struct {
	prefix string
	new    func() transcodableJSON
}

var (
	jsonPrefixes = []string{
		kvstore.ClusterConfigPrefix,
		nodestore.NodeStorePrefix,
		kvstore.StateToCachePrefix(nodestore.NodeStorePrefix),
		clustermeshstore.ServiceStorePrefix,
		kvstore.StateToCachePrefix(clustermeshstore.ServiceStorePrefix),
		mcsapitypes.ServiceExportStorePrefix,
		kvstore.StateToCachePrefix(mcsapitypes.ServiceExportStorePrefix),
		ipcache.IPIdentitiesPath,
		kvstore.StateToCachePrefix(ipcache.IPIdentitiesPath),
	}
	blobPrefixes = []string{
		kvstore.HeartbeatPath,
		kvstore.InitLockPath,
		kvstore.SyncedPrefix,
		identitycache.IdentitiesPath,
		kvstore.StateToCachePrefix(identitycache.IdentitiesPath),
	}
	blobTranscodableJSONPrefixes = []prefixTranscodableJSONInfo{
		{
			prefix: endpointslice.EndpointSliceStorePrefix,
			new:    func() transcodableJSON { return &endpointslice.ClusterEndpointSlice{} },
		},
		{
			prefix: kvstore.StateToCachePrefix(endpointslice.EndpointSliceStorePrefix),
			new:    func() transcodableJSON { return &endpointslice.ClusterEndpointSlice{} },
		},
	}
)

type keyType string

const (
	keyTypeJSON                 keyType = "json"
	keyTypeBlob                 keyType = "blob"
	keyTypeBlobTranscodableJSON keyType = "blob-transcodable-json"
	keyTypeUnknown              keyType = "unknown"
)

func hasKeyPrefix(key string, prefixes []string) bool {
	for _, prefix := range prefixes {
		if key == prefix || strings.HasPrefix(key, prefix+"/") {
			return true
		}
	}
	return false
}

func lookupPrefixTranscodableJSONInfo(key string) (prefixTranscodableJSONInfo, error) {
	for _, prefixTranscodableInfo := range blobTranscodableJSONPrefixes {
		if hasKeyPrefix(key, []string{prefixTranscodableInfo.prefix}) {
			return prefixTranscodableInfo, nil
		}
	}
	return prefixTranscodableJSONInfo{}, fmt.Errorf("key %q does not match any known blob-transcodable JSON prefix", key)
}

func getKeyType(key string) keyType {
	if hasKeyPrefix(key, jsonPrefixes) {
		return keyTypeJSON
	}
	if hasKeyPrefix(key, blobPrefixes) {
		return keyTypeBlob
	}
	if _, err := lookupPrefixTranscodableJSONInfo(key); err == nil {
		return keyTypeBlobTranscodableJSON
	}
	return keyTypeUnknown
}

func relativeKey(prefixTranscodableInfo prefixTranscodableJSONInfo, key string) string {
	return strings.TrimPrefix(key, prefixTranscodableInfo.prefix+"/")
}

func transcodeToJSON(prefixTranscodableInfo prefixTranscodableJSONInfo, key string, value []byte) ([]byte, error) {
	val := prefixTranscodableInfo.new()
	if err := val.Unmarshal(relativeKey(prefixTranscodableInfo, key), value); err != nil {
		return nil, err
	}
	return val.MarshalJSON()
}

func transcodeFromJSON(prefixTranscodableInfo prefixTranscodableJSONInfo, value []byte) ([]byte, error) {
	val := prefixTranscodableInfo.new()
	if err := val.UnmarshalJSON(value); err != nil {
		return nil, err
	}

	return val.Marshal()
}
