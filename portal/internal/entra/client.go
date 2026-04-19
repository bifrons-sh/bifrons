// Package entra wraps the Microsoft Graph API calls the portal needs for the
// Entra-backed approval workflow: resolving a user's manager (approver), the
// groups they belong to (for policy scoping), and sending notification email
// through /sendMail.
//
// Auth uses the client-credentials flow (app registration with application
// permissions User.Read.All + Mail.Send). Tokens are cached in memory and
// refreshed ~60s before expiry.
//
// No Graph response bodies are ever echoed in logs — they can carry PII and
// access tokens. Only error classes (status code + operation) are surfaced.
package entra

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
)

// ErrNotFound signals Graph returned 404 for the requested resource (e.g. a
// user with no manager set, or a user object id that doesn't exist).
var ErrNotFound = errors.New("entra: not found")

// User is the trimmed-down Graph user shape the portal consumes.
type User struct {
	ID                string `json:"id"`
	DisplayName       string `json:"displayName,omitempty"`
	Mail              string `json:"mail,omitempty"`
	UserPrincipalName string `json:"userPrincipalName,omitempty"`
}

// Group mirrors the minimal Graph group shape.
type Group struct {
	ID          string `json:"id"`
	DisplayName string `json:"displayName,omitempty"`
}

// MailMessage is the portal-facing payload for /sendMail.
type MailMessage struct {
	To       []string
	Subject  string
	HTMLBody string
	TextBody string
}

// Client is the narrow interface the portal relies on. Production impl talks
// to Microsoft Graph; tests can plug in NewFakeClient.
type Client interface {
	Manager(ctx context.Context, userObjectID string) (User, error)
	Groups(ctx context.Context, userObjectID string) ([]Group, error)
	SendMail(ctx context.Context, from string, req MailMessage) error
	GetUser(ctx context.Context, userObjectID string) (User, error)
	// GroupMembers walks /groups/{id}/members and returns user-shaped members.
	// Used to resolve admin reachability when the operator wires the portal
	// against an Entra admin group instead of a single mailbox.
	GroupMembers(ctx context.Context, groupID string) ([]User, error)
}

// Config carries the minimal knobs needed to bootstrap the Graph client.
type Config struct {
	TenantID     string
	ClientID     string
	ClientSecret string
	// GraphBaseURL overrides https://graph.microsoft.com for tests. Leave empty in prod.
	GraphBaseURL string
	// TokenURL overrides https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token. Tests only.
	TokenURL string
	HTTPClient *http.Client
	Logger     *slog.Logger
}

// Enabled reports whether Config has the minimum fields to wire the client.
// Gate construction on this so the portal can run without Entra.
func (c *Config) Enabled() bool {
	return c != nil && c.TenantID != "" && c.ClientID != "" && c.ClientSecret != ""
}

// NewFromConfig builds a Graph-backed Client. Caller must check cfg.Enabled()
// first; passing an empty Config yields an error.
func NewFromConfig(ctx context.Context, cfg Config) (*graphClient, error) {
	if !cfg.Enabled() {
		return nil, errors.New("entra: config missing tenant/client/secret")
	}
	base := cfg.GraphBaseURL
	if base == "" {
		base = "https://graph.microsoft.com"
	}
	tokenURL := cfg.TokenURL
	if tokenURL == "" {
		tokenURL = "https://login.microsoftonline.com/" + cfg.TenantID + "/oauth2/v2.0/token"
	}
	httpc := cfg.HTTPClient
	if httpc == nil {
		httpc = &http.Client{Timeout: 15 * time.Second}
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}

	cc := &clientcredentials.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		TokenURL:     tokenURL,
		Scopes:       []string{base + "/.default"},
	}
	// Refresh 60s before expiry — avoids in-flight requests hitting expired
	// tokens on slow networks.
	tokenCtx := context.WithValue(ctx, oauth2.HTTPClient, httpc)
	src := oauth2.ReuseTokenSourceWithExpiry(nil, cc.TokenSource(tokenCtx), 60*time.Second)

	return &graphClient{
		base:   strings.TrimRight(base, "/"),
		httpc:  httpc,
		tokens: src,
		logger: logger.With("component", "entra"),
	}, nil
}

// graphClient is the production Client implementation.
type graphClient struct {
	base   string
	httpc  *http.Client
	tokens oauth2.TokenSource
	logger *slog.Logger
}

// Manager returns the direct manager of the Entra user. 404 → ErrNotFound so
// callers can fall back to an admin approver.
func (g *graphClient) Manager(ctx context.Context, userObjectID string) (User, error) {
	var u User
	err := g.do(ctx, http.MethodGet, "/v1.0/users/"+url.PathEscape(userObjectID)+"/manager", nil, &u)
	if err != nil {
		return User{}, err
	}
	return u, nil
}

// GetUser fetches a user object by id/UPN.
func (g *graphClient) GetUser(ctx context.Context, userObjectID string) (User, error) {
	var u User
	err := g.do(ctx, http.MethodGet, "/v1.0/users/"+url.PathEscape(userObjectID), nil, &u)
	if err != nil {
		return User{}, err
	}
	return u, nil
}

// Groups walks /users/{id}/memberOf, following @odata.nextLink pagination.
// Non-group directoryObjects (e.g. directoryRoles) are filtered out — the
// caller only cares about group memberships for policy scoping.
func (g *graphClient) Groups(ctx context.Context, userObjectID string) ([]Group, error) {
	path := "/v1.0/users/" + url.PathEscape(userObjectID) + "/memberOf?$select=id,displayName,@odata.type&$top=200"
	var out []Group
	for {
		var page struct {
			Value []struct {
				Type        string `json:"@odata.type"`
				ID          string `json:"id"`
				DisplayName string `json:"displayName"`
			} `json:"value"`
			NextLink string `json:"@odata.nextLink"`
		}
		if err := g.do(ctx, http.MethodGet, path, nil, &page); err != nil {
			return nil, err
		}
		for _, v := range page.Value {
			// Keep only group-shaped directoryObjects so Admin/Directory roles
			// don't pollute group-scoped policy evaluation.
			if v.Type != "" && !strings.EqualFold(v.Type, "#microsoft.graph.group") {
				continue
			}
			out = append(out, Group{ID: v.ID, DisplayName: v.DisplayName})
		}
		if page.NextLink == "" {
			return out, nil
		}
		// nextLink is an absolute URL; strip the base so we can reuse do().
		path = strings.TrimPrefix(page.NextLink, g.base)
		if path == page.NextLink {
			// Different host in nextLink — bail rather than follow an
			// unexpected origin.
			return out, nil
		}
	}
}

// GroupMembers walks /groups/{id}/members, paginating via @odata.nextLink.
// Filters to user-shaped directoryObjects so nested groups / service principals
// don't leak into the email recipient list.
func (g *graphClient) GroupMembers(ctx context.Context, groupID string) ([]User, error) {
	path := "/v1.0/groups/" + url.PathEscape(groupID) + "/members?$select=id,displayName,mail,userPrincipalName,@odata.type&$top=200"
	var out []User
	for {
		var page struct {
			Value []struct {
				Type              string `json:"@odata.type"`
				ID                string `json:"id"`
				DisplayName       string `json:"displayName"`
				Mail              string `json:"mail"`
				UserPrincipalName string `json:"userPrincipalName"`
			} `json:"value"`
			NextLink string `json:"@odata.nextLink"`
		}
		if err := g.do(ctx, http.MethodGet, path, nil, &page); err != nil {
			return nil, err
		}
		for _, v := range page.Value {
			if v.Type != "" && !strings.EqualFold(v.Type, "#microsoft.graph.user") {
				continue
			}
			out = append(out, User{
				ID:                v.ID,
				DisplayName:       v.DisplayName,
				Mail:              v.Mail,
				UserPrincipalName: v.UserPrincipalName,
			})
		}
		if page.NextLink == "" {
			return out, nil
		}
		path = strings.TrimPrefix(page.NextLink, g.base)
		if path == page.NextLink {
			return out, nil
		}
	}
}

// sendMailPayload mirrors the Graph /sendMail request shape.
type sendMailPayload struct {
	Message         sendMailMessage `json:"message"`
	SaveToSentItems bool            `json:"saveToSentItems"`
}

type sendMailMessage struct {
	Subject      string              `json:"subject"`
	Body         sendMailBody        `json:"body"`
	ToRecipients []sendMailRecipient `json:"toRecipients"`
}

type sendMailBody struct {
	ContentType string `json:"contentType"`
	Content     string `json:"content"`
}

type sendMailRecipient struct {
	EmailAddress sendMailAddress `json:"emailAddress"`
}

type sendMailAddress struct {
	Address string `json:"address"`
}

// SendMail posts to /users/{from}/sendMail. HTML body is preferred when set;
// otherwise falls back to plain text. Caller decides the From mailbox — the
// service principal must hold Mail.Send application permission for it.
func (g *graphClient) SendMail(ctx context.Context, from string, req MailMessage) error {
	if from == "" {
		return errors.New("entra: sendMail from is empty")
	}
	if len(req.To) == 0 {
		return errors.New("entra: sendMail needs at least one recipient")
	}
	contentType := "Text"
	content := req.TextBody
	if req.HTMLBody != "" {
		contentType = "HTML"
		content = req.HTMLBody
	}
	payload := sendMailPayload{
		Message: sendMailMessage{
			Subject: req.Subject,
			Body:    sendMailBody{ContentType: contentType, Content: content},
		},
		// Approval notifications are transactional — no point persisting to
		// Sent Items and cluttering the sender's mailbox.
		SaveToSentItems: false,
	}
	for _, to := range req.To {
		payload.Message.ToRecipients = append(payload.Message.ToRecipients, sendMailRecipient{EmailAddress: sendMailAddress{Address: to}})
	}
	return g.do(ctx, http.MethodPost, "/v1.0/users/"+url.PathEscape(from)+"/sendMail", payload, nil)
}

// do executes a Graph HTTP request, attaching the bearer token. Response bodies
// are decoded into out when non-nil; 2xx with no body (sendMail returns 202) is
// treated as success regardless of out.
func (g *graphClient) do(ctx context.Context, method, path string, body, out any) error {
	var reqBody io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("entra: marshal %s: %w", path, err)
		}
		reqBody = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, g.base+path, reqBody)
	if err != nil {
		return fmt.Errorf("entra: build request: %w", err)
	}
	tok, err := g.tokens.Token()
	if err != nil {
		// Don't log err.Error() — oauth2 errors can include the token endpoint
		// URL and occasionally body fragments; keep it to the class.
		g.logger.Error("entra_token_fetch_failed", "path", path)
		return fmt.Errorf("entra: token fetch failed")
	}
	req.Header.Set("Authorization", "Bearer "+tok.AccessToken)
	req.Header.Set("Accept", "application/json")
	if reqBody != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := g.httpc.Do(req)
	if err != nil {
		g.logger.Error("entra_http_failed", "method", method, "path", path)
		return fmt.Errorf("entra: http %s %s: %w", method, path, err)
	}
	defer func() { _, _ = io.Copy(io.Discard, resp.Body); _ = resp.Body.Close() }()

	switch {
	case resp.StatusCode == http.StatusNotFound:
		return ErrNotFound
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		if out == nil || resp.StatusCode == http.StatusNoContent || resp.ContentLength == 0 {
			return nil
		}
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil && !errors.Is(err, io.EOF) {
			return fmt.Errorf("entra: decode %s: %w", path, err)
		}
		return nil
	default:
		// Log only the status code class — the body may carry tokens or PII.
		g.logger.Warn("entra_graph_error", "method", method, "path", path, "status", resp.StatusCode)
		return fmt.Errorf("entra: %s %s returned status %d", method, path, resp.StatusCode)
	}
}
