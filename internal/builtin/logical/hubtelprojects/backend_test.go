// Copyright (c) Hubtel. Internal fork addition — not for upstream contribution.
// SPDX-License-Identifier: MPL-2.0

package hubtelprojects

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stretchr/testify/require"
)

func getTestBackend(t *testing.T) (*backend, logical.Storage) {
	t.Helper()

	config := logical.TestBackendConfig()
	config.StorageView = &logical.InmemStorage{}

	b := Backend()
	require.NoError(t, b.Setup(context.Background(), config))

	return b, config.StorageView
}

func doRequest(t *testing.T, b *backend, s logical.Storage, op logical.Operation, path string, data map[string]any) *logical.Response {
	t.Helper()

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: op,
		Path:      path,
		Data:      data,
		Storage:   s,
	})
	require.NoError(t, err)
	require.False(t, resp.IsError(), "unexpected error response: %#v", resp)
	return resp
}

func TestProjectLifecycle(t *testing.T) {
	b, s := getTestBackend(t)

	doRequest(t, b, s, logical.CreateOperation, "projects/payments-api", map[string]any{
		"display_name": "Payments API",
		"members":      "Alice@hubtel.com, bob@hubtel.com",
	})

	resp := doRequest(t, b, s, logical.ReadOperation, "projects/payments-api", nil)
	require.Equal(t, "payments-api", resp.Data["name"])
	require.Equal(t, "Payments API", resp.Data["display_name"])
	require.Equal(t, []string{"alice@hubtel.com", "bob@hubtel.com"}, resp.Data["members"])
	require.Equal(t, []string{"dev", "staging", "prod"}, resp.Data["environments"])
	require.Equal(t, "manual", resp.Data["source"])

	resp = doRequest(t, b, s, logical.ListOperation, "projects/", nil)
	require.Equal(t, []string{"payments-api"}, resp.Data["keys"])

	// Invalid names are rejected.
	badResp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "projects/bad..name",
		Storage:   s,
	})
	require.NoError(t, err)
	require.True(t, badResp.IsError())

	doRequest(t, b, s, logical.DeleteOperation, "projects/payments-api", nil)
	resp = doRequest(t, b, s, logical.ListOperation, "projects/", nil)
	require.Empty(t, resp.Data)
}

func TestSecretVersioningAndCAS(t *testing.T) {
	b, s := getTestBackend(t)

	doRequest(t, b, s, logical.CreateOperation, "projects/payments-api", nil)

	// First write.
	resp := doRequest(t, b, s, logical.CreateOperation, "projects/payments-api/dev/secrets/DATABASE_URL", map[string]any{
		"value": "postgres://one",
	})
	require.Equal(t, 1, resp.Data["version"])

	// Second write becomes version 2; version 1 stays readable.
	doRequest(t, b, s, logical.UpdateOperation, "projects/payments-api/dev/secrets/DATABASE_URL", map[string]any{
		"value": "postgres://two",
	})

	resp = doRequest(t, b, s, logical.ReadOperation, "projects/payments-api/dev/secrets/DATABASE_URL", nil)
	require.Equal(t, "postgres://two", resp.Data["value"])
	require.Equal(t, 2, resp.Data["version"])

	resp = doRequest(t, b, s, logical.ReadOperation, "projects/payments-api/dev/secrets/DATABASE_URL", map[string]any{
		"version": 1,
	})
	require.Equal(t, "postgres://one", resp.Data["value"])

	// Stale check-and-set is rejected.
	casResp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "projects/payments-api/dev/secrets/DATABASE_URL",
		Storage:   s,
		Data:      map[string]any{"value": "postgres://three", "cas": 1},
	})
	require.NoError(t, err)
	require.True(t, casResp.IsError())

	// Matching check-and-set succeeds.
	doRequest(t, b, s, logical.UpdateOperation, "projects/payments-api/dev/secrets/DATABASE_URL", map[string]any{
		"value": "postgres://three",
		"cas":   2,
	})

	// Generated secrets work and land in the listing.
	resp = doRequest(t, b, s, logical.CreateOperation, "projects/payments-api/dev/secrets/JWT_KEY", map[string]any{
		"generate": true,
	})
	require.Equal(t, 1, resp.Data["version"])

	resp = doRequest(t, b, s, logical.ListOperation, "projects/payments-api/dev/secrets/", nil)
	require.ElementsMatch(t, []string{"DATABASE_URL", "JWT_KEY"}, resp.Data["keys"])

	// Unknown environment is rejected.
	envResp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "projects/payments-api/qa/secrets/DATABASE_URL",
		Storage:   s,
	})
	require.NoError(t, err)
	require.True(t, envResp.IsError())
}

func TestVersionPruning(t *testing.T) {
	b, s := getTestBackend(t)

	doRequest(t, b, s, logical.CreateOperation, "projects/p1", nil)
	doRequest(t, b, s, logical.CreateOperation, "projects/p1/dev/secrets/KEY", map[string]any{"value": "v1"})
	doRequest(t, b, s, logical.UpdateOperation, "projects/p1/dev/secrets/KEY/config", map[string]any{"max_versions": 2})

	for _, v := range []string{"v2", "v3", "v4"} {
		doRequest(t, b, s, logical.UpdateOperation, "projects/p1/dev/secrets/KEY", map[string]any{"value": v})
	}

	resp := doRequest(t, b, s, logical.ReadOperation, "projects/p1/dev/secrets/KEY/history", nil)
	require.Equal(t, 4, resp.Data["current_version"])
	versions := resp.Data["versions"].(map[string]any)
	require.Len(t, versions, 2)
	require.Contains(t, versions, "3")
	require.Contains(t, versions, "4")

	// Pruned version data is gone from storage.
	entry, err := s.Get(context.Background(), "data/p1/dev/KEY/v1")
	require.NoError(t, err)
	require.Nil(t, entry)
}

func TestRotationWithSignedWebhook(t *testing.T) {
	b, s := getTestBackend(t)

	var mu sync.Mutex
	var gotBody []byte
	var gotSignature string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		gotBody = body
		gotSignature = r.Header.Get("X-Rotation-Signature")
		mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	doRequest(t, b, s, logical.UpdateOperation, "config", map[string]any{
		"webhook_signing_secret": "topsecret",
	})
	doRequest(t, b, s, logical.CreateOperation, "projects/payments-api", nil)
	doRequest(t, b, s, logical.UpdateOperation, "projects/payments-api/webhooks", map[string]any{
		"urls": server.URL,
	})
	doRequest(t, b, s, logical.CreateOperation, "projects/payments-api/dev/secrets/JWT_KEY", map[string]any{
		"generate": true,
	})

	before := doRequest(t, b, s, logical.ReadOperation, "projects/payments-api/dev/secrets/JWT_KEY", nil)

	resp := doRequest(t, b, s, logical.UpdateOperation, "projects/payments-api/dev/secrets/JWT_KEY/rotate", nil)
	require.Equal(t, 2, resp.Data["version"])
	require.Empty(t, resp.Warnings)

	after := doRequest(t, b, s, logical.ReadOperation, "projects/payments-api/dev/secrets/JWT_KEY", nil)
	require.NotEqual(t, before.Data["value"], after.Data["value"])
	require.Equal(t, true, after.Data["rotated"])

	// The webhook was signed and carries no secret value.
	mu.Lock()
	defer mu.Unlock()
	var event map[string]any
	require.NoError(t, json.Unmarshal(gotBody, &event))
	require.Equal(t, "secret.rotated", event["event"])
	require.Equal(t, "payments-api", event["project"])
	require.Equal(t, "dev", event["environment"])
	require.Equal(t, "JWT_KEY", event["secret"])
	require.Equal(t, float64(2), event["version"])
	require.NotContains(t, string(gotBody), after.Data["value"].(string))

	mac := hmac.New(sha256.New, []byte("topsecret"))
	mac.Write(gotBody)
	require.Equal(t, "sha256="+hex.EncodeToString(mac.Sum(nil)), gotSignature)
}

func TestScheduledRotationViaPeriodicFunc(t *testing.T) {
	b, s := getTestBackend(t)

	doRequest(t, b, s, logical.CreateOperation, "projects/p1", nil)
	doRequest(t, b, s, logical.CreateOperation, "projects/p1/dev/secrets/API_KEY", map[string]any{"generate": true})
	doRequest(t, b, s, logical.UpdateOperation, "projects/p1/dev/secrets/API_KEY/config", map[string]any{
		"auto_rotate":     true,
		"rotation_period": "1h",
	})

	// Backdate the last rotation to force the schedule due.
	meta, err := getSecretMeta(context.Background(), s, "p1", "dev", "API_KEY")
	require.NoError(t, err)
	meta.Rotation.LastRotatedTime = time.Now().UTC().Add(-2 * time.Hour)
	require.NoError(t, putSecretMeta(context.Background(), s, "p1", "dev", "API_KEY", meta))

	require.NoError(t, b.periodicFunc(context.Background(), &logical.Request{Storage: s}))

	resp := doRequest(t, b, s, logical.ReadOperation, "projects/p1/dev/secrets/API_KEY", nil)
	require.Equal(t, 2, resp.Data["version"])
	require.Equal(t, true, resp.Data["rotated"])

	// Not due again immediately.
	require.NoError(t, b.periodicFunc(context.Background(), &logical.Request{Storage: s}))
	resp = doRequest(t, b, s, logical.ReadOperation, "projects/p1/dev/secrets/API_KEY", nil)
	require.Equal(t, 2, resp.Data["version"])
}

func TestCCISync(t *testing.T) {
	b, s := getTestBackend(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/productteams", r.URL.Path)
		require.Equal(t, "Bearer cci-token", r.Header.Get("Authorization"))

		page := r.URL.Query().Get("Page")
		w.Header().Set("Content-Type", "application/json")
		if page == "1" {
			w.Write([]byte(`{"code":200,"data":{"results":[{"id":"payments-api","name":"Payments API","members":[{"id":"1","name":"Alice","email":"Alice@hubtel.com"}]}],"page":1,"totalPages":2}}`))
			return
		}
		w.Write([]byte(`{"code":200,"data":{"results":[{"id":"inventory-web","name":"Inventory Web","members":[{"id":"2","name":"Bob","email":"bob@hubtel.com"}]}],"page":2,"totalPages":2}}`))
	}))
	defer server.Close()

	doRequest(t, b, s, logical.UpdateOperation, "config", map[string]any{
		"cci_url":                  server.URL,
		"cci_authorization":        "Bearer cci-token",
		"create_projects_from_cci": true,
	})

	resp := doRequest(t, b, s, logical.UpdateOperation, "sync", nil)
	require.Equal(t, 2, resp.Data["project_count"])

	resp = doRequest(t, b, s, logical.ReadOperation, "projects/payments-api", nil)
	require.Equal(t, "cci", resp.Data["source"])
	require.Equal(t, "Payments API", resp.Data["display_name"])
	require.Equal(t, []string{"alice@hubtel.com"}, resp.Data["members"])

	resp = doRequest(t, b, s, logical.ListOperation, "projects/", nil)
	require.ElementsMatch(t, []string{"payments-api", "inventory-web"}, resp.Data["keys"])
}

func TestMembershipEnforcement(t *testing.T) {
	config := logical.TestBackendConfig()
	config.StorageView = &logical.InmemStorage{}
	sysView := logical.TestSystemView()
	sysView.EntityVal = &logical.Entity{
		ID:   "entity-alice",
		Name: "entity-alice",
		Aliases: []*logical.Alias{
			{Name: "alice@hubtel.com", MountType: "jwt"},
		},
	}
	config.System = sysView

	b := Backend()
	require.NoError(t, b.Setup(context.Background(), config))
	s := config.StorageView

	doRequest(t, b, s, logical.UpdateOperation, "config", map[string]any{"enforce_membership": true})
	doRequest(t, b, s, logical.CreateOperation, "projects/payments-api", map[string]any{
		"members": "alice@hubtel.com",
	})
	doRequest(t, b, s, logical.CreateOperation, "projects/inventory-web", map[string]any{
		"members": "bob@hubtel.com",
	})

	// Alice (matching entity alias) can use her project.
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "projects/payments-api/dev/secrets/KEY",
		Storage:   s,
		EntityID:  "entity-alice",
		Data:      map[string]any{"generate": true},
	})
	require.NoError(t, err)
	require.False(t, resp.IsError())

	// Alice cannot touch a project she is not a member of.
	_, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "projects/inventory-web/dev/secrets/KEY",
		Storage:   s,
		EntityID:  "entity-alice",
	})
	require.ErrorIs(t, err, logical.ErrPermissionDenied)

	// A token without an entity is rejected while enforcement is on.
	_, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "projects/payments-api/dev/secrets/OTHER",
		Storage:   s,
		Data:      map[string]any{"generate": true},
	})
	require.ErrorIs(t, err, logical.ErrPermissionDenied)

	// Self-service creation seeds the creator as a member, so the new
	// project is immediately usable.
	resp, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "projects/alice-sandbox",
		Storage:   s,
		EntityID:  "entity-alice",
	})
	require.NoError(t, err)
	require.False(t, resp.IsError())

	resp, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "projects/alice-sandbox/dev/secrets/KEY",
		Storage:   s,
		EntityID:  "entity-alice",
		Data:      map[string]any{"generate": true},
	})
	require.NoError(t, err)
	require.False(t, resp.IsError())

	project, err := getProject(context.Background(), s, "alice-sandbox")
	require.NoError(t, err)
	require.Equal(t, []string{"alice@hubtel.com"}, project.Members)
}
