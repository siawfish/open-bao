// Copyright (c) Hubtel. Internal fork addition — not for upstream contribution.
// SPDX-License-Identifier: MPL-2.0

package hubtelprojects

import (
	"context"
	"time"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

func secretBaseFields() map[string]*framework.FieldSchema {
	return map[string]*framework.FieldSchema{
		"project": {
			Type:        framework.TypeString,
			Description: "Name of the project.",
		},
		"environment": {
			Type:        framework.TypeString,
			Description: "Environment within the project.",
		},
	}
}

func pathListSecrets(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "projects/" + framework.GenericNameRegex("project") + "/" + framework.GenericNameRegex("environment") + "/secrets/?$",

		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefixHubtelProjects,
			OperationSuffix: "secrets",
		},

		Fields: secretBaseFields(),

		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ListOperation: &framework.PathOperation{
				Callback: b.pathSecretList,
			},
		},

		HelpSynopsis: "List secrets in a project environment.",
	}
}

func pathSecrets(b *backend) *framework.Path {
	fields := secretBaseFields()
	fields["name"] = &framework.FieldSchema{
		Type:        framework.TypeString,
		Description: "Name of the secret.",
	}
	fields["value"] = &framework.FieldSchema{
		Type:        framework.TypeString,
		Description: "Secret value. Required unless generate=true.",
	}
	fields["generate"] = &framework.FieldSchema{
		Type:        framework.TypeBool,
		Default:     false,
		Description: "Generate a strong 256-bit random value instead of supplying one.",
	}
	fields["cas"] = &framework.FieldSchema{
		Type:        framework.TypeInt,
		Default:     -1,
		Description: "Check-and-set: the write only succeeds if this equals the current version (0 means the secret must not exist yet).",
	}
	fields["version"] = &framework.FieldSchema{
		Type:        framework.TypeInt,
		Default:     0,
		Description: "On read, the version to return; defaults to the latest.",
	}

	return &framework.Path{
		Pattern: "projects/" + framework.GenericNameRegex("project") + "/" + framework.GenericNameRegex("environment") + "/secrets/" + framework.GenericNameRegex("name") + "$",

		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefixHubtelProjects,
			OperationSuffix: "secret",
		},

		Fields: fields,

		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.pathSecretRead,
			},
			logical.CreateOperation: &framework.PathOperation{
				Callback: b.pathSecretWrite,
			},
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathSecretWrite,
			},
			logical.DeleteOperation: &framework.PathOperation{
				Callback: b.pathSecretDelete,
			},
		},

		ExistenceCheck: b.secretExistenceCheck,

		HelpSynopsis:    "Create, read, and delete versioned secrets.",
		HelpDescription: "Every write creates a new retained version. Reads return the latest version unless ?version=N is supplied.",
	}
}

func pathSecretHistory(b *backend) *framework.Path {
	fields := secretBaseFields()
	fields["name"] = &framework.FieldSchema{
		Type:        framework.TypeString,
		Description: "Name of the secret.",
	}

	return &framework.Path{
		Pattern: "projects/" + framework.GenericNameRegex("project") + "/" + framework.GenericNameRegex("environment") + "/secrets/" + framework.GenericNameRegex("name") + "/history$",

		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefixHubtelProjects,
			OperationSuffix: "secret-history",
		},

		Fields: fields,

		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.pathSecretHistoryRead,
			},
		},

		HelpSynopsis: "Read version history for a secret (metadata only, no values).",
	}
}

func pathSecretRotationConfig(b *backend) *framework.Path {
	fields := secretBaseFields()
	fields["name"] = &framework.FieldSchema{
		Type:        framework.TypeString,
		Description: "Name of the secret.",
	}
	fields["auto_rotate"] = &framework.FieldSchema{
		Type:        framework.TypeBool,
		Description: "Enable scheduled automatic rotation.",
	}
	fields["rotation_period"] = &framework.FieldSchema{
		Type:        framework.TypeDurationSecond,
		Description: "Interval between automatic rotations. Minimum 60s.",
	}
	fields["max_versions"] = &framework.FieldSchema{
		Type:        framework.TypeInt,
		Description: "Number of retained versions. Defaults to 10.",
	}

	return &framework.Path{
		Pattern: "projects/" + framework.GenericNameRegex("project") + "/" + framework.GenericNameRegex("environment") + "/secrets/" + framework.GenericNameRegex("name") + "/config$",

		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefixHubtelProjects,
			OperationSuffix: "secret-rotation-configuration",
		},

		Fields: fields,

		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.pathSecretRotationConfigRead,
			},
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathSecretRotationConfigWrite,
			},
		},

		HelpSynopsis: "Read or set the rotation schedule for a secret.",
	}
}

func pathSecretRotate(b *backend) *framework.Path {
	fields := secretBaseFields()
	fields["name"] = &framework.FieldSchema{
		Type:        framework.TypeString,
		Description: "Name of the secret.",
	}
	fields["value"] = &framework.FieldSchema{
		Type:        framework.TypeString,
		Description: "New value for externally-managed credentials. Omit to generate a strong random value.",
	}

	return &framework.Path{
		Pattern: "projects/" + framework.GenericNameRegex("project") + "/" + framework.GenericNameRegex("environment") + "/secrets/" + framework.GenericNameRegex("name") + "/rotate$",

		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefixHubtelProjects,
			OperationSuffix: "rotate",
			OperationVerb:   "rotate",
		},

		Fields: fields,

		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathSecretRotateWrite,
			},
		},

		HelpSynopsis:    "Rotate a secret immediately.",
		HelpDescription: "Writes a new version (generated unless value is supplied) and sends signed, value-free webhook notifications to the project's endpoints.",
	}
}

func (b *backend) secretExistenceCheck(ctx context.Context, req *logical.Request, d *framework.FieldData) (bool, error) {
	meta, err := getSecretMeta(ctx, req.Storage, d.Get("project").(string), d.Get("environment").(string), d.Get("name").(string))
	if err != nil {
		return false, err
	}
	return meta != nil, nil
}

func (b *backend) pathSecretList(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	projectName := d.Get("project").(string)
	env := d.Get("environment").(string)

	_, _, errResp, err := b.loadProjectForRequest(ctx, req, projectName, env)
	if errResp != nil || err != nil {
		return errResp, err
	}

	names, err := req.Storage.List(ctx, "meta/"+projectName+"/"+env+"/")
	if err != nil {
		return nil, err
	}
	return logical.ListResponse(names), nil
}

func (b *backend) pathSecretRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	projectName := d.Get("project").(string)
	env := d.Get("environment").(string)
	name := d.Get("name").(string)

	_, _, errResp, err := b.loadProjectForRequest(ctx, req, projectName, env)
	if errResp != nil || err != nil {
		return errResp, err
	}

	meta, err := getSecretMeta(ctx, req.Storage, projectName, env, name)
	if err != nil {
		return nil, err
	}
	if meta == nil {
		return nil, nil
	}

	version := d.Get("version").(int)
	if version <= 0 {
		version = meta.CurrentVersion
	}

	vm, ok := meta.Versions[versionKey(version)]
	if !ok {
		return logical.ErrorResponse("version %d of secret %q does not exist or has been pruned", version, name), nil
	}

	data, err := getVersionData(ctx, req.Storage, projectName, env, name, version)
	if err != nil {
		return nil, err
	}
	if data == nil {
		return logical.ErrorResponse("version %d of secret %q has no stored data", version, name), nil
	}

	return &logical.Response{
		Data: map[string]any{
			"name":            name,
			"value":           data.Value,
			"version":         version,
			"current_version": meta.CurrentVersion,
			"created_time":    vm.CreatedTime.UTC().Format(time.RFC3339),
			"rotated":         vm.Rotated,
			"generated":       vm.Generated,
		},
	}, nil
}

func (b *backend) pathSecretWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	projectName := d.Get("project").(string)
	env := d.Get("environment").(string)
	name := d.Get("name").(string)

	if err := validateName("secret", name); err != nil {
		return logical.ErrorResponse("%s", err.Error()), nil
	}

	_, _, errResp, err := b.loadProjectForRequest(ctx, req, projectName, env)
	if errResp != nil || err != nil {
		return errResp, err
	}

	value := d.Get("value").(string)
	generate := d.Get("generate").(bool)
	if generate {
		if value != "" {
			return logical.ErrorResponse("provide either value or generate=true, not both"), nil
		}
		value, err = generateSecretValue()
		if err != nil {
			return nil, err
		}
	} else if value == "" {
		return logical.ErrorResponse("value is required unless generate=true"), nil
	}

	var cas *int
	if casRaw := d.Get("cas").(int); casRaw >= 0 {
		cas = &casRaw
	}

	version, err := b.writeSecretVersion(ctx, req.Storage, projectName, env, name, value, false, generate, cas)
	if err != nil {
		return logical.ErrorResponse("%s", err.Error()), nil
	}

	return &logical.Response{
		Data: map[string]any{
			"version": version,
		},
	}, nil
}

func (b *backend) pathSecretDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	projectName := d.Get("project").(string)
	env := d.Get("environment").(string)
	name := d.Get("name").(string)

	_, _, errResp, err := b.loadProjectForRequest(ctx, req, projectName, env)
	if errResp != nil || err != nil {
		return errResp, err
	}

	meta, err := getSecretMeta(ctx, req.Storage, projectName, env, name)
	if err != nil {
		return nil, err
	}
	if meta == nil {
		return nil, nil
	}

	for vk := range meta.Versions {
		version, err := parseVersionKey(vk)
		if err != nil {
			continue
		}
		if err := req.Storage.Delete(ctx, dataStorageKey(projectName, env, name, version)); err != nil {
			return nil, err
		}
	}
	if err := req.Storage.Delete(ctx, metaStorageKey(projectName, env, name)); err != nil {
		return nil, err
	}
	return nil, nil
}

func (b *backend) pathSecretHistoryRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	projectName := d.Get("project").(string)
	env := d.Get("environment").(string)
	name := d.Get("name").(string)

	_, _, errResp, err := b.loadProjectForRequest(ctx, req, projectName, env)
	if errResp != nil || err != nil {
		return errResp, err
	}

	meta, err := getSecretMeta(ctx, req.Storage, projectName, env, name)
	if err != nil {
		return nil, err
	}
	if meta == nil {
		return nil, nil
	}

	versions := make(map[string]any, len(meta.Versions))
	for vk, vm := range meta.Versions {
		versions[vk] = map[string]any{
			"created_time": vm.CreatedTime.UTC().Format(time.RFC3339),
			"rotated":      vm.Rotated,
			"generated":    vm.Generated,
		}
	}

	data := map[string]any{
		"name":            name,
		"current_version": meta.CurrentVersion,
		"max_versions":    meta.maxVersions(),
		"versions":        versions,
		"auto_rotate":     meta.Rotation.AutoRotate,
		"rotation_period": meta.Rotation.PeriodSeconds,
	}
	if !meta.Rotation.LastRotatedTime.IsZero() {
		data["last_rotated_time"] = meta.Rotation.LastRotatedTime.UTC().Format(time.RFC3339)
	}
	return &logical.Response{Data: data}, nil
}

func (b *backend) pathSecretRotationConfigRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	projectName := d.Get("project").(string)
	env := d.Get("environment").(string)
	name := d.Get("name").(string)

	_, _, errResp, err := b.loadProjectForRequest(ctx, req, projectName, env)
	if errResp != nil || err != nil {
		return errResp, err
	}

	meta, err := getSecretMeta(ctx, req.Storage, projectName, env, name)
	if err != nil {
		return nil, err
	}
	if meta == nil {
		return logical.ErrorResponse("secret %q does not exist", name), nil
	}

	data := map[string]any{
		"auto_rotate":     meta.Rotation.AutoRotate,
		"rotation_period": meta.Rotation.PeriodSeconds,
		"max_versions":    meta.maxVersions(),
	}
	if !meta.Rotation.LastRotatedTime.IsZero() {
		data["last_rotated_time"] = meta.Rotation.LastRotatedTime.UTC().Format(time.RFC3339)
	}
	return &logical.Response{Data: data}, nil
}

func (b *backend) pathSecretRotationConfigWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	projectName := d.Get("project").(string)
	env := d.Get("environment").(string)
	name := d.Get("name").(string)

	_, _, errResp, err := b.loadProjectForRequest(ctx, req, projectName, env)
	if errResp != nil || err != nil {
		return errResp, err
	}

	meta, err := getSecretMeta(ctx, req.Storage, projectName, env, name)
	if err != nil {
		return nil, err
	}
	if meta == nil {
		return logical.ErrorResponse("secret %q does not exist; write it first", name), nil
	}

	if raw, ok := d.GetOk("auto_rotate"); ok {
		meta.Rotation.AutoRotate = raw.(bool)
	}
	if raw, ok := d.GetOk("rotation_period"); ok {
		period := int64(raw.(int))
		if period < minRotationPeriodSeconds {
			return logical.ErrorResponse("rotation_period must be at least %ds", minRotationPeriodSeconds), nil
		}
		meta.Rotation.PeriodSeconds = period
	}
	if raw, ok := d.GetOk("max_versions"); ok {
		mv := raw.(int)
		if mv < 1 {
			return logical.ErrorResponse("max_versions must be at least 1"), nil
		}
		meta.MaxVersions = mv
	}

	if meta.Rotation.AutoRotate && meta.Rotation.PeriodSeconds <= 0 {
		return logical.ErrorResponse("auto_rotate requires rotation_period"), nil
	}

	meta.UpdatedTime = time.Now().UTC()
	if err := putSecretMeta(ctx, req.Storage, projectName, env, name, meta); err != nil {
		return nil, err
	}
	return nil, nil
}

func (b *backend) pathSecretRotateWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	projectName := d.Get("project").(string)
	env := d.Get("environment").(string)
	name := d.Get("name").(string)

	cfg, project, errResp, err := b.loadProjectForRequest(ctx, req, projectName, env)
	if errResp != nil || err != nil {
		return errResp, err
	}

	meta, err := getSecretMeta(ctx, req.Storage, projectName, env, name)
	if err != nil {
		return nil, err
	}
	if meta == nil {
		return logical.ErrorResponse("secret %q does not exist; write it first", name), nil
	}

	value := d.Get("value").(string)
	version, deliveryErrs, err := b.rotateSecret(ctx, req.Storage, cfg, project, env, name, value)
	if err != nil {
		return logical.ErrorResponse("%s", err.Error()), nil
	}

	resp := &logical.Response{
		Data: map[string]any{
			"version":    version,
			"rotated_at": time.Now().UTC().Format(time.RFC3339),
		},
	}
	for _, derr := range deliveryErrs {
		resp.AddWarning("webhook delivery failed: " + derr.Error())
	}
	return resp, nil
}
