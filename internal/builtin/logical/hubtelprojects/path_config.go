// Copyright (c) Hubtel. Internal fork addition — not for upstream contribution.
// SPDX-License-Identifier: MPL-2.0

package hubtelprojects

import (
	"context"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

func pathConfig(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "config$",

		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefixHubtelProjects,
			OperationSuffix: "configuration",
		},

		Fields: map[string]*framework.FieldSchema{
			"cci_url": {
				Type:        framework.TypeString,
				Description: "Base URL of the CCI API used for product-team reconciliation.",
			},
			"cci_authorization": {
				Type:        framework.TypeString,
				Description: "Authorization header value sent to the CCI API. Not returned on read.",
			},
			"sync_interval": {
				Type:        framework.TypeDurationSecond,
				Description: "Interval between CCI membership reconciliations. Defaults to 5m.",
			},
			"create_projects_from_cci": {
				Type:        framework.TypeBool,
				Description: "If true, CCI reconciliation creates missing projects; otherwise it only updates membership of existing projects.",
			},
			"webhook_signing_secret": {
				Type:        framework.TypeString,
				Description: "HMAC-SHA256 secret used to sign rotation webhook payloads. Not returned on read.",
			},
			"enforce_membership": {
				Type:        framework.TypeBool,
				Description: "If true, secret operations require the caller's identity entity to resolve to a project member email.",
			},
			"default_environments": {
				Type:        framework.TypeCommaStringSlice,
				Description: "Environments assigned to newly created projects. Defaults to dev,staging,prod.",
			},
		},

		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.pathConfigRead,
			},
			logical.CreateOperation: &framework.PathOperation{
				Callback: b.pathConfigWrite,
			},
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathConfigWrite,
			},
		},

		ExistenceCheck: b.configExistenceCheck,

		HelpSynopsis:    "Configure CCI reconciliation, webhook signing, and access enforcement.",
		HelpDescription: "Engine-wide settings: CCI endpoint and credentials, reconciliation interval, webhook signing secret, membership enforcement, and default environments.",
	}
}

func (b *backend) configExistenceCheck(ctx context.Context, req *logical.Request, _ *framework.FieldData) (bool, error) {
	entry, err := req.Storage.Get(ctx, storageConfigKey)
	if err != nil {
		return false, err
	}
	return entry != nil, nil
}

func (b *backend) pathConfigRead(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	cfg, err := getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	return &logical.Response{
		Data: map[string]any{
			"cci_url":                    cfg.CCIURL,
			"cci_authorization_set":      cfg.CCIAuthorization != "",
			"sync_interval_seconds":      int64(cfg.syncInterval().Seconds()),
			"create_projects_from_cci":   cfg.CreateProjectsFromCCI,
			"webhook_signing_secret_set": cfg.WebhookSigningSecret != "",
			"enforce_membership":         cfg.EnforceMembership,
			"default_environments":       cfg.environments(),
		},
	}, nil
}

func (b *backend) pathConfigWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	cfg, err := getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	if raw, ok := d.GetOk("cci_url"); ok {
		cfg.CCIURL = raw.(string)
	}
	if raw, ok := d.GetOk("cci_authorization"); ok {
		cfg.CCIAuthorization = raw.(string)
	}
	if raw, ok := d.GetOk("sync_interval"); ok {
		cfg.SyncIntervalSeconds = int64(raw.(int))
	}
	if raw, ok := d.GetOk("create_projects_from_cci"); ok {
		cfg.CreateProjectsFromCCI = raw.(bool)
	}
	if raw, ok := d.GetOk("webhook_signing_secret"); ok {
		cfg.WebhookSigningSecret = raw.(string)
	}
	if raw, ok := d.GetOk("enforce_membership"); ok {
		cfg.EnforceMembership = raw.(bool)
	}
	if raw, ok := d.GetOk("default_environments"); ok {
		envs := raw.([]string)
		for _, env := range envs {
			if err := validateName("environment", env); err != nil {
				return logical.ErrorResponse("%s", err.Error()), nil
			}
		}
		cfg.DefaultEnvironments = envs
	}

	if err := putConfig(ctx, req.Storage, cfg); err != nil {
		return nil, err
	}
	return nil, nil
}
