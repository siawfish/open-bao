// Copyright (c) Hubtel. Internal fork addition — not for upstream contribution.
// SPDX-License-Identifier: MPL-2.0

package hubtelprojects

import (
	"context"
	"net/url"
	"time"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

func pathListProjects(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "projects/?$",

		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefixHubtelProjects,
			OperationSuffix: "projects",
		},

		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ListOperation: &framework.PathOperation{
				Callback: b.pathProjectList,
			},
		},

		HelpSynopsis: "List projects.",
	}
}

func pathProjects(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "projects/" + framework.GenericNameRegex("project") + "$",

		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefixHubtelProjects,
			OperationSuffix: "project",
		},

		Fields: map[string]*framework.FieldSchema{
			"project": {
				Type:        framework.TypeString,
				Description: "Name of the project.",
			},
			"display_name": {
				Type:        framework.TypeString,
				Description: "Human-friendly project name.",
			},
			"environments": {
				Type:        framework.TypeCommaStringSlice,
				Description: "Environments for this project. Defaults to the engine's default environments.",
			},
			"members": {
				Type:        framework.TypeCommaStringSlice,
				Description: "Member emails granted access when membership enforcement is enabled.",
			},
		},

		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.pathProjectRead,
			},
			logical.CreateOperation: &framework.PathOperation{
				Callback: b.pathProjectWrite,
			},
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathProjectWrite,
			},
			logical.DeleteOperation: &framework.PathOperation{
				Callback: b.pathProjectDelete,
			},
		},

		ExistenceCheck: b.projectExistenceCheck,

		HelpSynopsis: "Create, read, and delete projects.",
	}
}

func pathProjectMembers(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "projects/" + framework.GenericNameRegex("project") + "/members$",

		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefixHubtelProjects,
			OperationSuffix: "members",
		},

		Fields: map[string]*framework.FieldSchema{
			"project": {
				Type:        framework.TypeString,
				Description: "Name of the project.",
			},
			"members": {
				Type:        framework.TypeCommaStringSlice,
				Description: "Member emails granted access when membership enforcement is enabled.",
			},
		},

		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.pathProjectMembersRead,
			},
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathProjectMembersWrite,
			},
		},

		HelpSynopsis:    "Read or set project membership.",
		HelpDescription: "Manual membership writes are overwritten by the next CCI reconciliation for CCI-sourced projects.",
	}
}

func pathProjectWebhooks(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "projects/" + framework.GenericNameRegex("project") + "/webhooks$",

		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefixHubtelProjects,
			OperationSuffix: "webhooks",
		},

		Fields: map[string]*framework.FieldSchema{
			"project": {
				Type:        framework.TypeString,
				Description: "Name of the project.",
			},
			"urls": {
				Type:        framework.TypeCommaStringSlice,
				Description: "HTTP(S) endpoints notified after a rotation in this project.",
			},
		},

		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.pathProjectWebhooksRead,
			},
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathProjectWebhooksWrite,
			},
		},

		HelpSynopsis: "Read or set the rotation webhook endpoints for a project.",
	}
}

func (b *backend) projectExistenceCheck(ctx context.Context, req *logical.Request, d *framework.FieldData) (bool, error) {
	project, err := getProject(ctx, req.Storage, d.Get("project").(string))
	if err != nil {
		return false, err
	}
	return project != nil, nil
}

func (b *backend) pathProjectList(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	names, err := req.Storage.List(ctx, "project/")
	if err != nil {
		return nil, err
	}
	return logical.ListResponse(names), nil
}

func (b *backend) pathProjectRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("project").(string)

	_, project, errResp, err := b.loadProjectForRequest(ctx, req, name, "")
	if errResp != nil || err != nil {
		return errResp, err
	}

	return &logical.Response{
		Data: map[string]any{
			"name":           project.Name,
			"display_name":   project.DisplayName,
			"environments":   project.Environments,
			"members":        project.Members,
			"source":         project.Source,
			"cci_product_id": project.CCIProductID,
			"webhook_urls":   project.WebhookURLs,
			"created_time":   project.CreatedTime.UTC().Format(time.RFC3339),
			"updated_time":   project.UpdatedTime.UTC().Format(time.RFC3339),
		},
	}, nil
}

func (b *backend) pathProjectWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("project").(string)
	if err := validateName("project", name); err != nil {
		return logical.ErrorResponse("%s", err.Error()), nil
	}

	cfg, err := getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	project, err := getProject(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	if project == nil {
		project = &projectEntry{
			Name:         name,
			Environments: cfg.environments(),
			Source:       "manual",
			CreatedTime:  now,
		}
		// Self-service creation: seed membership with the creator so the
		// project is immediately usable under membership enforcement.
		if _, ok := d.GetOk("members"); !ok {
			project.Members = normalizeEmails(b.callerEmails(req))
		}
	}

	if raw, ok := d.GetOk("display_name"); ok {
		project.DisplayName = raw.(string)
	}
	if raw, ok := d.GetOk("environments"); ok {
		envs := raw.([]string)
		if len(envs) == 0 {
			return logical.ErrorResponse("a project needs at least one environment"), nil
		}
		for _, env := range envs {
			if err := validateName("environment", env); err != nil {
				return logical.ErrorResponse("%s", err.Error()), nil
			}
		}
		project.Environments = envs
	}
	if raw, ok := d.GetOk("members"); ok {
		project.Members = normalizeEmails(raw.([]string))
	}
	project.UpdatedTime = now

	if err := putProject(ctx, req.Storage, project); err != nil {
		return nil, err
	}
	return nil, nil
}

func (b *backend) pathProjectDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("project").(string)

	project, err := getProject(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}
	if project == nil {
		return nil, nil
	}

	// Remove all secret metadata and version data beneath the project.
	for _, prefix := range []string{"meta/" + name + "/", "data/" + name + "/"} {
		if err := deletePrefix(ctx, req.Storage, prefix); err != nil {
			return nil, err
		}
	}

	if err := req.Storage.Delete(ctx, projectStorageKey(name)); err != nil {
		return nil, err
	}
	return nil, nil
}

// deletePrefix recursively deletes every entry under a storage prefix.
func deletePrefix(ctx context.Context, s logical.Storage, prefix string) error {
	keys, err := s.List(ctx, prefix)
	if err != nil {
		return err
	}
	for _, key := range keys {
		full := prefix + key
		if len(key) > 0 && key[len(key)-1] == '/' {
			if err := deletePrefix(ctx, s, full); err != nil {
				return err
			}
			continue
		}
		if err := s.Delete(ctx, full); err != nil {
			return err
		}
	}
	return nil
}

func (b *backend) pathProjectMembersRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("project").(string)

	_, project, errResp, err := b.loadProjectForRequest(ctx, req, name, "")
	if errResp != nil || err != nil {
		return errResp, err
	}

	return &logical.Response{
		Data: map[string]any{
			"members": project.Members,
			"source":  project.Source,
		},
	}, nil
}

func (b *backend) pathProjectMembersWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("project").(string)

	project, err := getProject(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}
	if project == nil {
		return logical.ErrorResponse("project %q does not exist", name), nil
	}

	project.Members = normalizeEmails(d.Get("members").([]string))
	project.UpdatedTime = time.Now().UTC()
	if err := putProject(ctx, req.Storage, project); err != nil {
		return nil, err
	}

	resp := &logical.Response{}
	if project.Source == "cci" {
		resp.AddWarning("this project is reconciled from CCI; membership will be overwritten on the next sync")
	}
	return resp, nil
}

func (b *backend) pathProjectWebhooksRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("project").(string)

	_, project, errResp, err := b.loadProjectForRequest(ctx, req, name, "")
	if errResp != nil || err != nil {
		return errResp, err
	}

	return &logical.Response{
		Data: map[string]any{
			"urls": project.WebhookURLs,
		},
	}, nil
}

func (b *backend) pathProjectWebhooksWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("project").(string)

	project, err := getProject(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}
	if project == nil {
		return logical.ErrorResponse("project %q does not exist", name), nil
	}

	urls := d.Get("urls").([]string)
	for _, raw := range urls {
		u, err := url.Parse(raw)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return logical.ErrorResponse("invalid webhook url %q: must be absolute http(s)", raw), nil
		}
	}

	project.WebhookURLs = urls
	project.UpdatedTime = time.Now().UTC()
	if err := putProject(ctx, req.Storage, project); err != nil {
		return nil, err
	}
	return nil, nil
}
