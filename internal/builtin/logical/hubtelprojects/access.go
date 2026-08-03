// Copyright (c) Hubtel. Internal fork addition — not for upstream contribution.
// SPDX-License-Identifier: MPL-2.0

package hubtelprojects

import (
	"context"
	"fmt"
	"strings"

	"github.com/openbao/openbao/sdk/v2/logical"
)

// requireProjectAccess enforces CCI-derived membership when the engine is
// configured with enforce_membership=true. OpenBao ACL policies still apply
// before any request reaches the engine; this is a second, data-driven layer
// that scopes engineers to the products they belong to.
func (b *backend) requireProjectAccess(ctx context.Context, req *logical.Request, cfg *engineConfig, project *projectEntry) error {
	if !cfg.EnforceMembership {
		return nil
	}

	if req.EntityID == "" {
		return fmt.Errorf("membership enforcement is enabled and this token has no identity entity; use an auth method that creates entities (for example the jwt/oidc method) or disable enforce_membership")
	}

	candidates, err := b.entityCandidates(req.EntityID)
	if err != nil {
		return err
	}

	if !project.hasMember(candidates) {
		return fmt.Errorf("not a member of project %q", project.Name)
	}
	return nil
}

// entityCandidates resolves an identity entity into the set of lowercase
// identifiers (entity name, alias names, email metadata) used for membership
// matching.
func (b *backend) entityCandidates(entityID string) (map[string]struct{}, error) {
	entity, err := b.System().EntityInfo(entityID)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve identity entity: %w", err)
	}
	if entity == nil {
		return nil, fmt.Errorf("identity entity %q not found", entityID)
	}

	candidates := make(map[string]struct{})
	add := func(v string) {
		v = strings.ToLower(strings.TrimSpace(v))
		if v != "" {
			candidates[v] = struct{}{}
		}
	}
	add(entity.Name)
	if email, ok := entity.Metadata["email"]; ok {
		add(email)
	}
	for _, alias := range entity.Aliases {
		add(alias.Name)
		if email, ok := alias.Metadata["email"]; ok {
			add(email)
		}
	}
	return candidates, nil
}

// callerEmails returns the email-shaped identifiers of the requesting entity,
// used to seed membership for self-service project creation. Returns nil when
// the request has no resolvable entity.
func (b *backend) callerEmails(req *logical.Request) []string {
	if req.EntityID == "" {
		return nil
	}
	candidates, err := b.entityCandidates(req.EntityID)
	if err != nil {
		return nil
	}
	var emails []string
	for candidate := range candidates {
		if strings.Contains(candidate, "@") {
			emails = append(emails, candidate)
		}
	}
	return emails
}

// loadProjectForRequest resolves the project and environment from a request
// and applies membership enforcement. Returns a user-facing error response
// when the request should be rejected.
func (b *backend) loadProjectForRequest(ctx context.Context, req *logical.Request, projectName, env string) (*engineConfig, *projectEntry, *logical.Response, error) {
	cfg, err := getConfig(ctx, req.Storage)
	if err != nil {
		return nil, nil, nil, err
	}

	project, err := getProject(ctx, req.Storage, projectName)
	if err != nil {
		return nil, nil, nil, err
	}
	if project == nil {
		return nil, nil, logical.ErrorResponse("project %q does not exist", projectName), nil
	}
	if env != "" && !project.hasEnvironment(env) {
		return nil, nil, logical.ErrorResponse("project %q has no environment %q", projectName, env), nil
	}

	if err := b.requireProjectAccess(ctx, req, cfg, project); err != nil {
		resp := logical.ErrorResponse("%s", err.Error())
		resp.AddWarning("access denied by hubtel-projects membership enforcement")
		return nil, nil, resp, logical.ErrPermissionDenied
	}

	return cfg, project, nil, nil
}
