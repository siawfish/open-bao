// Copyright (c) Hubtel. Internal fork addition — not for upstream contribution.
// SPDX-License-Identifier: MPL-2.0

package hubtelprojects

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

const operationPrefixHubtelProjects = "hubtel-projects"

func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b := Backend()
	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}
	return b, nil
}

func Backend() *backend {
	var b backend
	b.Backend = &framework.Backend{
		Help: strings.TrimSpace(backendHelp),

		PathsSpecial: &logical.Paths{
			SealWrapStorage: []string{
				"config",
				"data/",
			},
		},

		Paths: []*framework.Path{
			pathConfig(&b),
			pathListProjects(&b),
			pathProjects(&b),
			pathProjectMembers(&b),
			pathProjectWebhooks(&b),
			pathListSecrets(&b),
			pathSecrets(&b),
			pathSecretHistory(&b),
			pathSecretRotationConfig(&b),
			pathSecretRotate(&b),
			pathSyncNow(&b),
		},

		Secrets:      []*framework.Secret{},
		BackendType:  logical.TypeLogical,
		PeriodicFunc: b.periodicFunc,
	}

	b.httpClient = &http.Client{Timeout: 10 * time.Second}

	return &b
}

type backend struct {
	*framework.Backend

	httpClient *http.Client

	// periodicMu serializes periodic rotation/sync work against concurrent
	// invocations.
	periodicMu sync.Mutex
}

const backendHelp = `
The Hubtel projects secrets engine manages product-scoped, versioned secrets.

Each project maps to a CCI product team and holds per-environment secrets.
Every write creates a new retained version. Secrets can be rotated on demand
or automatically on a schedule; rotations emit signed, value-free webhook
notifications. Project membership can be reconciled from the CCI product-team
API and enforced per request using the caller's identity entity.
`
