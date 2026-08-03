// Copyright (c) Hubtel. Internal fork addition — not for upstream contribution.
// SPDX-License-Identifier: MPL-2.0

package hubtelprojects

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

type rotationEvent struct {
	Event       string `json:"event"`
	Project     string `json:"project"`
	Environment string `json:"environment"`
	Secret      string `json:"secret"`
	Version     int    `json:"version"`
	RotatedAt   string `json:"rotated_at"`
}

// fireRotationWebhooks POSTs a signed, value-free rotation notification to
// every webhook URL configured on the project. Delivery is best-effort: each
// failure is logged and returned, but never blocks the rotation itself.
func (b *backend) fireRotationWebhooks(ctx context.Context, cfg *engineConfig, project *projectEntry, env, name string, version int) []error {
	if len(project.WebhookURLs) == 0 {
		return nil
	}

	payload, err := json.Marshal(&rotationEvent{
		Event:       "secret.rotated",
		Project:     project.Name,
		Environment: env,
		Secret:      name,
		Version:     version,
		RotatedAt:   time.Now().UTC().Format(time.RFC3339),
	})
	if err != nil {
		return []error{err}
	}

	var signature string
	if cfg.WebhookSigningSecret != "" {
		mac := hmac.New(sha256.New, []byte(cfg.WebhookSigningSecret))
		mac.Write(payload)
		signature = "sha256=" + hex.EncodeToString(mac.Sum(nil))
	}

	var errs []error
	for _, url := range project.WebhookURLs {
		if err := b.deliverWebhook(ctx, url, payload, signature); err != nil {
			wrapped := fmt.Errorf("%s: %w", url, err)
			errs = append(errs, wrapped)
			b.Logger().Warn("rotation webhook delivery failed",
				"project", project.Name, "environment", env, "secret", name, "url", url, "error", err)
		}
	}
	return errs
}

func (b *backend) deliverWebhook(ctx context.Context, url string, payload []byte, signature string) error {
	reqCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if signature != "" {
		req.Header.Set("X-Rotation-Signature", signature)
	}

	resp, err := b.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("unexpected status %d", resp.StatusCode)
	}
	return nil
}
