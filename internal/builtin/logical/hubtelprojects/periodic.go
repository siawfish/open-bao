// Copyright (c) Hubtel. Internal fork addition — not for upstream contribution.
// SPDX-License-Identifier: MPL-2.0

package hubtelprojects

import (
	"context"
	"time"

	"github.com/openbao/openbao/sdk/v2/logical"
)

// periodicFunc is invoked by OpenBao's rollback manager roughly once a
// minute. It performs two duties: rotating secrets whose schedule is due, and
// reconciling CCI membership when the sync interval has elapsed.
func (b *backend) periodicFunc(ctx context.Context, req *logical.Request) error {
	b.periodicMu.Lock()
	defer b.periodicMu.Unlock()

	cfg, err := getConfig(ctx, req.Storage)
	if err != nil {
		return err
	}

	if err := b.rotateDueSecrets(ctx, req.Storage, cfg); err != nil {
		b.Logger().Error("scheduled rotation pass failed", "error", err)
	}

	if cfg.CCIURL != "" {
		state, err := getSyncState(ctx, req.Storage)
		if err != nil {
			return err
		}
		if state.LastSyncTime.IsZero() || time.Since(state.LastSyncTime) >= cfg.syncInterval() {
			if _, err := b.runCCISync(ctx, req.Storage, cfg); err != nil {
				b.Logger().Error("CCI reconciliation failed", "error", err)
			}
		}
	}

	return nil
}

// rotateDueSecrets scans every secret's rotation config and rotates the ones
// whose period has elapsed.
func (b *backend) rotateDueSecrets(ctx context.Context, s logical.Storage, cfg *engineConfig) error {
	projects, err := s.List(ctx, "project/")
	if err != nil {
		return err
	}

	now := time.Now().UTC()
	for _, projectName := range projects {
		project, err := getProject(ctx, s, projectName)
		if err != nil || project == nil {
			continue
		}

		for _, env := range project.Environments {
			names, err := s.List(ctx, "meta/"+project.Name+"/"+env+"/")
			if err != nil {
				return err
			}
			for _, name := range names {
				meta, err := getSecretMeta(ctx, s, project.Name, env, name)
				if err != nil || meta == nil {
					continue
				}
				if !meta.Rotation.due(now) {
					continue
				}

				if _, _, err := b.rotateSecret(ctx, s, cfg, project, env, name, ""); err != nil {
					b.Logger().Error("scheduled rotation failed",
						"project", project.Name, "environment", env, "secret", name, "error", err)
					continue
				}
				b.Logger().Info("rotated secret on schedule",
					"project", project.Name, "environment", env, "secret", name)
			}
		}
	}

	return nil
}
