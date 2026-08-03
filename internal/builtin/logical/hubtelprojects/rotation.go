// Copyright (c) Hubtel. Internal fork addition — not for upstream contribution.
// SPDX-License-Identifier: MPL-2.0

package hubtelprojects

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/openbao/openbao/sdk/v2/logical"
)

// generateSecretValue returns a URL-safe encoding of 256 random bits.
func generateSecretValue() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// writeSecretVersion appends a new version, prunes versions beyond
// max_versions, and returns the new version number. When cas is non-nil the
// write fails unless *cas equals the current version (0 for "must not exist").
func (b *backend) writeSecretVersion(ctx context.Context, s logical.Storage, project, env, name, value string, rotated, generated bool, cas *int) (int, error) {
	meta, err := getSecretMeta(ctx, s, project, env, name)
	if err != nil {
		return 0, err
	}

	now := time.Now().UTC()
	if meta == nil {
		meta = &secretMeta{
			Versions:    make(map[string]*versionMeta),
			CreatedTime: now,
		}
	}

	if cas != nil && *cas != meta.CurrentVersion {
		return 0, fmt.Errorf("check-and-set parameter (%d) did not match current version (%d)", *cas, meta.CurrentVersion)
	}

	version := meta.CurrentVersion + 1

	dataEntry, err := logical.StorageEntryJSON(dataStorageKey(project, env, name, version), &versionData{Value: value})
	if err != nil {
		return 0, err
	}
	if err := s.Put(ctx, dataEntry); err != nil {
		return 0, err
	}

	meta.CurrentVersion = version
	meta.Versions[versionKey(version)] = &versionMeta{
		CreatedTime: now,
		Rotated:     rotated,
		Generated:   generated,
	}
	if rotated {
		meta.Rotation.LastRotatedTime = now
	}
	meta.UpdatedTime = now

	// Prune versions older than the retention window.
	oldest := version - meta.maxVersions()
	for vk := range meta.Versions {
		v, err := parseVersionKey(vk)
		if err != nil || v > oldest {
			continue
		}
		if err := s.Delete(ctx, dataStorageKey(project, env, name, v)); err != nil {
			return 0, err
		}
		delete(meta.Versions, vk)
	}

	if err := putSecretMeta(ctx, s, project, env, name, meta); err != nil {
		return 0, err
	}
	return version, nil
}

// rotateSecret writes a new (generated or supplied) version and notifies the
// project's webhook endpoints. Webhook failures do not fail the rotation;
// they are returned for reporting.
func (b *backend) rotateSecret(ctx context.Context, s logical.Storage, cfg *engineConfig, project *projectEntry, env, name, value string) (int, []error, error) {
	var err error
	generated := value == ""
	if generated {
		value, err = generateSecretValue()
		if err != nil {
			return 0, nil, err
		}
	}

	version, err := b.writeSecretVersion(ctx, s, project.Name, env, name, value, true, generated, nil)
	if err != nil {
		return 0, nil, err
	}

	deliveryErrs := b.fireRotationWebhooks(ctx, cfg, project, env, name, version)
	return version, deliveryErrs, nil
}
