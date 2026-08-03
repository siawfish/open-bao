// Copyright (c) Hubtel. Internal fork addition — not for upstream contribution.
// SPDX-License-Identifier: MPL-2.0

package hubtelprojects

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

// The CCI product-team API contract, matching Hubtel's CCI controller:
// GET {cci_url}/productteams?Page=N&PageSize=250
//   -> {"code":200,"data":{"results":[...],"page":N,"totalPages":M}}
type cciMember struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Email string `json:"email"`
}

type cciProductTeam struct {
	ID      string      `json:"id"`
	Name    string      `json:"name"`
	Members []cciMember `json:"members"`
}

type cciPage struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    *struct {
		Results    []cciProductTeam `json:"results"`
		Page       int              `json:"page"`
		TotalPages int              `json:"totalPages"`
	} `json:"data"`
}

const cciPageSize = 250

// fetchAllProductTeams walks the paginated CCI product-team endpoint.
func (b *backend) fetchAllProductTeams(ctx context.Context, cfg *engineConfig) ([]cciProductTeam, error) {
	var teams []cciProductTeam

	page := 1
	totalPages := 1
	for page <= totalPages {
		u, err := url.Parse(strings.TrimSuffix(cfg.CCIURL, "/") + "/productteams")
		if err != nil {
			return nil, err
		}
		q := u.Query()
		q.Set("Page", strconv.Itoa(page))
		q.Set("PageSize", strconv.Itoa(cciPageSize))
		u.RawQuery = q.Encode()

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Accept", "application/json")
		if cfg.CCIAuthorization != "" {
			req.Header.Set("Authorization", cfg.CCIAuthorization)
		}

		resp, err := b.httpClient.Do(req)
		if err != nil {
			return nil, fmt.Errorf("CCI request for page %d failed: %w", page, err)
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, 10<<20))
		resp.Body.Close()
		if err != nil {
			return nil, err
		}

		var parsed cciPage
		if err := json.Unmarshal(body, &parsed); err != nil {
			return nil, fmt.Errorf("CCI page %d returned invalid JSON (status %d): %w", page, resp.StatusCode, err)
		}
		if resp.StatusCode != http.StatusOK || parsed.Code != 200 || parsed.Data == nil {
			msg := parsed.Message
			if msg == "" {
				msg = resp.Status
			}
			return nil, fmt.Errorf("CCI product snapshot failed on page %d: %s", page, msg)
		}

		teams = append(teams, parsed.Data.Results...)
		if parsed.Data.TotalPages > totalPages {
			totalPages = parsed.Data.TotalPages
		}
		page++
	}

	return teams, nil
}

// syncFromCCI reconciles project membership from the CCI snapshot. Projects
// sourced from CCI get their membership replaced exactly; secret data is
// always retained, including for teams that disappear from CCI.
func (b *backend) syncFromCCI(ctx context.Context, s logical.Storage, cfg *engineConfig) (int, error) {
	teams, err := b.fetchAllProductTeams(ctx, cfg)
	if err != nil {
		return 0, err
	}

	now := time.Now().UTC()
	count := 0
	for _, team := range teams {
		name := team.ID
		if validateName("project", name) != nil {
			b.Logger().Warn("skipping CCI team with unusable id", "id", team.ID, "name", team.Name)
			continue
		}

		project, err := getProject(ctx, s, name)
		if err != nil {
			return count, err
		}
		if project == nil {
			if !cfg.CreateProjectsFromCCI {
				continue
			}
			project = &projectEntry{
				Name:         name,
				Environments: cfg.environments(),
				CreatedTime:  now,
			}
		}

		members := make([]string, 0, len(team.Members))
		for _, m := range team.Members {
			members = append(members, m.Email)
		}

		project.DisplayName = team.Name
		project.Members = normalizeEmails(members)
		project.Source = "cci"
		project.CCIProductID = team.ID
		project.UpdatedTime = now

		if err := putProject(ctx, s, project); err != nil {
			return count, err
		}
		count++
	}

	return count, nil
}

// runCCISync executes a reconciliation and records its outcome in sync state.
func (b *backend) runCCISync(ctx context.Context, s logical.Storage, cfg *engineConfig) (*syncState, error) {
	state, err := getSyncState(ctx, s)
	if err != nil {
		return nil, err
	}

	count, syncErr := b.syncFromCCI(ctx, s, cfg)
	state.LastSyncTime = time.Now().UTC()
	state.ProjectCount = count
	if syncErr != nil {
		state.LastSyncError = syncErr.Error()
	} else {
		state.LastSyncError = ""
	}

	if err := putSyncState(ctx, s, state); err != nil {
		return nil, err
	}
	return state, syncErr
}

func pathSyncNow(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "sync$",

		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefixHubtelProjects,
			OperationSuffix: "sync",
			OperationVerb:   "sync",
		},

		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.pathSyncRead,
			},
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathSyncWrite,
			},
		},

		HelpSynopsis:    "Trigger or inspect CCI membership reconciliation.",
		HelpDescription: "Read returns the last reconciliation outcome. Write triggers an immediate reconciliation.",
	}
}

func (b *backend) pathSyncRead(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	state, err := getSyncState(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	data := map[string]any{
		"project_count":   state.ProjectCount,
		"last_sync_error": state.LastSyncError,
	}
	if !state.LastSyncTime.IsZero() {
		data["last_sync_time"] = state.LastSyncTime.UTC().Format(time.RFC3339)
	}
	return &logical.Response{Data: data}, nil
}

func (b *backend) pathSyncWrite(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	cfg, err := getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if cfg.CCIURL == "" {
		return logical.ErrorResponse("cci_url is not configured"), nil
	}

	state, syncErr := b.runCCISync(ctx, req.Storage, cfg)
	if syncErr != nil {
		return logical.ErrorResponse("CCI sync failed: %s", syncErr.Error()), nil
	}

	return &logical.Response{
		Data: map[string]any{
			"project_count":  state.ProjectCount,
			"last_sync_time": state.LastSyncTime.UTC().Format(time.RFC3339),
		},
	}, nil
}
