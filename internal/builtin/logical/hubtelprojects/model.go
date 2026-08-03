// Copyright (c) Hubtel. Internal fork addition — not for upstream contribution.
// SPDX-License-Identifier: MPL-2.0

package hubtelprojects

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/openbao/openbao/sdk/v2/logical"
)

const (
	storageConfigKey    = "config"
	storageSyncStateKey = "sync/state"

	defaultSyncIntervalSeconds = 300
	defaultMaxVersions         = 10
	minRotationPeriodSeconds   = 60
)

var defaultEnvironments = []string{"dev", "staging", "prod"}

// nameRegexp restricts project, environment, and secret names to safe
// path-segment identifiers.
var nameRegexp = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]{0,127}$`)

type engineConfig struct {
	CCIURL                string   `json:"cci_url"`
	CCIAuthorization      string   `json:"cci_authorization"`
	SyncIntervalSeconds   int64    `json:"sync_interval_seconds"`
	CreateProjectsFromCCI bool     `json:"create_projects_from_cci"`
	WebhookSigningSecret  string   `json:"webhook_signing_secret"`
	EnforceMembership     bool     `json:"enforce_membership"`
	DefaultEnvironments   []string `json:"default_environments"`
}

func (c *engineConfig) syncInterval() time.Duration {
	if c.SyncIntervalSeconds <= 0 {
		return defaultSyncIntervalSeconds * time.Second
	}
	return time.Duration(c.SyncIntervalSeconds) * time.Second
}

func (c *engineConfig) environments() []string {
	if len(c.DefaultEnvironments) == 0 {
		return defaultEnvironments
	}
	return c.DefaultEnvironments
}

type projectEntry struct {
	Name         string    `json:"name"`
	DisplayName  string    `json:"display_name"`
	Environments []string  `json:"environments"`
	Members      []string  `json:"members"`
	Source       string    `json:"source"` // "manual" or "cci"
	CCIProductID string    `json:"cci_product_id,omitempty"`
	WebhookURLs  []string  `json:"webhook_urls"`
	CreatedTime  time.Time `json:"created_time"`
	UpdatedTime  time.Time `json:"updated_time"`
}

func (p *projectEntry) hasEnvironment(env string) bool {
	for _, e := range p.Environments {
		if e == env {
			return true
		}
	}
	return false
}

func (p *projectEntry) hasMember(candidates map[string]struct{}) bool {
	for _, m := range p.Members {
		if _, ok := candidates[strings.ToLower(m)]; ok {
			return true
		}
	}
	return false
}

type rotationConfig struct {
	AutoRotate      bool      `json:"auto_rotate"`
	PeriodSeconds   int64     `json:"period_seconds"`
	LastRotatedTime time.Time `json:"last_rotated_time"`
}

func (r *rotationConfig) due(now time.Time) bool {
	if !r.AutoRotate || r.PeriodSeconds <= 0 {
		return false
	}
	anchor := r.LastRotatedTime
	if anchor.IsZero() {
		return true
	}
	return !now.Before(anchor.Add(time.Duration(r.PeriodSeconds) * time.Second))
}

type versionMeta struct {
	CreatedTime time.Time `json:"created_time"`
	Rotated     bool      `json:"rotated"`
	// Generated is true when the value was produced by the engine rather
	// than supplied by the caller; generated secrets can be auto-rotated
	// without coordinating with an external system.
	Generated bool `json:"generated"`
}

type secretMeta struct {
	CurrentVersion int                     `json:"current_version"`
	MaxVersions    int                     `json:"max_versions"`
	Versions       map[string]*versionMeta `json:"versions"`
	Rotation       rotationConfig          `json:"rotation"`
	CreatedTime    time.Time               `json:"created_time"`
	UpdatedTime    time.Time               `json:"updated_time"`
}

func (m *secretMeta) maxVersions() int {
	if m.MaxVersions <= 0 {
		return defaultMaxVersions
	}
	return m.MaxVersions
}

type versionData struct {
	Value string `json:"value"`
}

type syncState struct {
	LastSyncTime  time.Time `json:"last_sync_time"`
	LastSyncError string    `json:"last_sync_error,omitempty"`
	ProjectCount  int       `json:"project_count"`
}

func projectStorageKey(project string) string {
	return "project/" + project
}

func metaStorageKey(project, env, name string) string {
	return fmt.Sprintf("meta/%s/%s/%s", project, env, name)
}

func dataStorageKey(project, env, name string, version int) string {
	return fmt.Sprintf("data/%s/%s/%s/v%d", project, env, name, version)
}

func validateName(kind, name string) error {
	if !nameRegexp.MatchString(name) {
		return fmt.Errorf("invalid %s name %q: must match %s", kind, name, nameRegexp.String())
	}
	return nil
}

func getConfig(ctx context.Context, s logical.Storage) (*engineConfig, error) {
	entry, err := s.Get(ctx, storageConfigKey)
	if err != nil {
		return nil, err
	}
	cfg := &engineConfig{}
	if entry != nil {
		if err := entry.DecodeJSON(cfg); err != nil {
			return nil, err
		}
	}
	return cfg, nil
}

func putConfig(ctx context.Context, s logical.Storage, cfg *engineConfig) error {
	entry, err := logical.StorageEntryJSON(storageConfigKey, cfg)
	if err != nil {
		return err
	}
	return s.Put(ctx, entry)
}

func getProject(ctx context.Context, s logical.Storage, name string) (*projectEntry, error) {
	entry, err := s.Get(ctx, projectStorageKey(name))
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}
	project := &projectEntry{}
	if err := entry.DecodeJSON(project); err != nil {
		return nil, err
	}
	return project, nil
}

func putProject(ctx context.Context, s logical.Storage, project *projectEntry) error {
	entry, err := logical.StorageEntryJSON(projectStorageKey(project.Name), project)
	if err != nil {
		return err
	}
	return s.Put(ctx, entry)
}

func getSecretMeta(ctx context.Context, s logical.Storage, project, env, name string) (*secretMeta, error) {
	entry, err := s.Get(ctx, metaStorageKey(project, env, name))
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}
	meta := &secretMeta{}
	if err := entry.DecodeJSON(meta); err != nil {
		return nil, err
	}
	return meta, nil
}

func putSecretMeta(ctx context.Context, s logical.Storage, project, env, name string, meta *secretMeta) error {
	entry, err := logical.StorageEntryJSON(metaStorageKey(project, env, name), meta)
	if err != nil {
		return err
	}
	return s.Put(ctx, entry)
}

func getVersionData(ctx context.Context, s logical.Storage, project, env, name string, version int) (*versionData, error) {
	entry, err := s.Get(ctx, dataStorageKey(project, env, name, version))
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}
	data := &versionData{}
	if err := entry.DecodeJSON(data); err != nil {
		return nil, err
	}
	return data, nil
}

func getSyncState(ctx context.Context, s logical.Storage) (*syncState, error) {
	entry, err := s.Get(ctx, storageSyncStateKey)
	if err != nil {
		return nil, err
	}
	state := &syncState{}
	if entry != nil {
		if err := entry.DecodeJSON(state); err != nil {
			return nil, err
		}
	}
	return state, nil
}

func putSyncState(ctx context.Context, s logical.Storage, state *syncState) error {
	entry, err := logical.StorageEntryJSON(storageSyncStateKey, state)
	if err != nil {
		return err
	}
	return s.Put(ctx, entry)
}

func normalizeEmails(in []string) []string {
	out := make([]string, 0, len(in))
	seen := make(map[string]struct{}, len(in))
	for _, e := range in {
		e = strings.ToLower(strings.TrimSpace(e))
		if e == "" {
			continue
		}
		if _, ok := seen[e]; ok {
			continue
		}
		seen[e] = struct{}{}
		out = append(out, e)
	}
	return out
}

func versionKey(v int) string {
	return strconv.Itoa(v)
}

func parseVersionKey(k string) (int, error) {
	return strconv.Atoi(k)
}
