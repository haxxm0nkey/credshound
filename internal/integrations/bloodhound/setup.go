package bloodhound

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

const savedQueryPrefix = "CredsHound - "

var newHTTPClient = func(timeout time.Duration, transport http.RoundTripper) *http.Client {
	return &http.Client{Timeout: timeout, Transport: transport}
}

type Options struct {
	Server       string
	Username     string
	Password     string
	Token        string
	NoIcons      bool
	NoQueries    bool
	ResetQueries bool
	NoVerifySSL  bool
	Timeout      time.Duration
}

type Result struct {
	IconsCreated   bool
	IconsUpdated   bool
	QueriesCreated int
	QueriesUpdated int
	QueriesSkipped int
	QueriesRemoved int
}

type NodeKind struct {
	Name        string
	Icon        string
	Color       string
	Description string
}

type SavedQuery struct {
	Name        string
	Description string
	Query       string
}

var NodeKinds = []NodeKind{
	{Name: "CHHost", Icon: "desktop", Color: "#64748B", Description: "Host scanned by CredsHound"},
	{Name: "CHLocalUser", Icon: "user", Color: "#38BDF8", Description: "Local or domain-style user context inferred from an exposure"},
	{Name: "CHExposure", Icon: "file-lines", Color: "#A78BFA", Description: "Credential exposure location such as a file, environment variable, or process environment"},
	{Name: "CHCredential", Icon: "key", Color: "#F97316", Description: "Deduplicated credential identity"},
	{Name: "CHService", Icon: "cube", Color: "#EAB308", Description: "Product or service a credential may authenticate to"},
}

var ObsoleteSavedQueryNames = []string{
	"CredsHound - Evidence Table",
	"CredsHound - Node Kind Counts",
}

var SavedQueries = []SavedQuery{
	{
		Name:        "CredsHound - Full Credential Graph",
		Description: "Show host-to-credential-to-service paths from CredsHound OpenGraph data.",
		Query: `MATCH p=(:CHHost)-[*1..4]->(:CHExposure)-[:CHRevealsCredential]->(:CHCredential)-[:CHAuthenticatesTo]->(:CHService)
RETURN p
LIMIT 50`,
	},
	{
		Name:        "CredsHound - Credential Reuse Across Hosts",
		Description: "Show graph paths for credentials discovered from more than one host or exposure location.",
		Query: `MATCH (h:CHHost)-[*1..3]->(e:CHExposure)-[:CHRevealsCredential]->(c:CHCredential)
WITH c, count(DISTINCT h) AS host_count, count(DISTINCT e) AS exposure_count
WHERE host_count > 1 OR exposure_count > 1
MATCH p=(:CHHost)-[*1..3]->(:CHExposure)-[:CHRevealsCredential]->(c)-[:CHAuthenticatesTo]->(:CHService)
RETURN p
LIMIT 100`,
	},
	{
		Name:        "CredsHound - Noisy Exposure Locations",
		Description: "Show exposure locations that reveal more than one credential.",
		Query: `MATCH (e:CHExposure)-[:CHRevealsCredential]->(c:CHCredential)
WITH e, count(DISTINCT c) AS credential_count
WHERE credential_count > 1
MATCH p=(:CHHost)-[*1..3]->(e)-[:CHRevealsCredential]->(:CHCredential)-[:CHAuthenticatesTo]->(:CHService)
RETURN p
LIMIT 100`,
	},
	{
		Name:        "CredsHound - Service Blast Radius",
		Description: "Show services that may be reachable from multiple hosts or exposure locations.",
		Query: `MATCH (h:CHHost)-[*1..3]->(e:CHExposure)-[:CHRevealsCredential]->(:CHCredential)-[:CHAuthenticatesTo]->(s:CHService)
WITH s, count(DISTINCT h) AS host_count, count(DISTINCT e) AS exposure_count
WHERE host_count > 1 OR exposure_count > 1
MATCH p=(:CHHost)-[*1..3]->(:CHExposure)-[:CHRevealsCredential]->(:CHCredential)-[:CHAuthenticatesTo]->(s)
RETURN p
LIMIT 100`,
	},
	{
		Name:        "CredsHound - Hosts With Multiple Credentials",
		Description: "Show hosts with more than one discovered credential exposure.",
		Query: `MATCH (h:CHHost)-[*1..3]->(:CHExposure)-[:CHRevealsCredential]->(c:CHCredential)
WITH h, count(DISTINCT c) AS credential_count
WHERE credential_count > 1
MATCH p=(h)-[*1..3]->(:CHExposure)-[:CHRevealsCredential]->(:CHCredential)-[:CHAuthenticatesTo]->(:CHService)
RETURN p
LIMIT 100`,
	},
	{
		Name:        "CredsHound - High Confidence Findings",
		Description: "Show high-confidence credential findings as graph paths.",
		Query: `MATCH p=(:CHHost)-[*1..3]->(:CHExposure)-[r:CHRevealsCredential]->(:CHCredential)-[:CHAuthenticatesTo]->(:CHService)
WHERE r.confidence = "high"
RETURN p
LIMIT 100`,
	},
	{
		Name:        "CredsHound - Observations Without Credentials",
		Description: "Show informational exposure observations that do not reveal a concrete credential.",
		Query: `MATCH p=(:CHHost)-[*1..3]->(e:CHExposure)
WHERE NOT (e)-[:CHRevealsCredential]->(:CHCredential)
RETURN p
LIMIT 100`,
	},
}

func Run(ctx context.Context, opts Options) (Result, error) {
	if strings.TrimSpace(opts.Server) == "" {
		return Result{}, fmt.Errorf("bloodhound server is required")
	}
	client, err := newClient(opts)
	if err != nil {
		return Result{}, err
	}
	if err := client.authenticate(ctx, opts); err != nil {
		return Result{}, err
	}

	var result Result
	if !opts.NoIcons {
		created, updated, err := client.registerNodeKinds(ctx, NodeKinds)
		if err != nil {
			return result, err
		}
		result.IconsCreated = created
		result.IconsUpdated = updated
	}

	if !opts.NoQueries {
		if opts.ResetQueries {
			removed, err := client.removeCredsHoundQueries(ctx)
			if err != nil {
				return result, err
			}
			result.QueriesRemoved = removed
		} else {
			removed, err := client.removeSavedQueriesByName(ctx, ObsoleteSavedQueryNames)
			if err != nil {
				return result, err
			}
			result.QueriesRemoved = removed
		}
		created, updated, skipped, err := client.registerSavedQueries(ctx, SavedQueries)
		if err != nil {
			return result, err
		}
		result.QueriesCreated = created
		result.QueriesUpdated = updated
		result.QueriesSkipped = skipped
	}
	return result, nil
}

type client struct {
	baseURL string
	http    *http.Client
	token   string
}

func newClient(opts Options) (*client, error) {
	base := strings.TrimRight(strings.TrimSpace(opts.Server), "/")
	if base == "" {
		return nil, fmt.Errorf("bloodhound server is required")
	}
	parsed, err := url.Parse(base)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return nil, fmt.Errorf("invalid bloodhound server URL %q", opts.Server)
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if opts.NoVerifySSL {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec
	}
	return &client{
		baseURL: base,
		http:    newHTTPClient(timeout, transport),
	}, nil
}

func (c *client) authenticate(ctx context.Context, opts Options) error {
	if token := strings.TrimSpace(opts.Token); token != "" {
		c.token = token
		return nil
	}
	if strings.TrimSpace(opts.Username) == "" || strings.TrimSpace(opts.Password) == "" {
		return fmt.Errorf("provide either -token or -username/-password")
	}

	var resp struct {
		SessionToken string `json:"session_token"`
		Data         struct {
			SessionToken string `json:"session_token"`
		} `json:"data"`
	}
	if err := c.request(ctx, http.MethodPost, "/api/v2/login", map[string]string{
		"login_method": "secret",
		"username":     opts.Username,
		"secret":       opts.Password,
	}, &resp); err != nil {
		return err
	}
	c.token = firstNonEmpty(resp.SessionToken, resp.Data.SessionToken)
	if c.token == "" {
		return fmt.Errorf("login succeeded but response did not include a session token")
	}
	return nil
}

func (c *client) registerNodeKinds(ctx context.Context, kinds []NodeKind) (bool, bool, error) {
	err := c.createNodeKinds(ctx, kinds)
	if err == nil {
		return true, false, nil
	}
	var statusErr statusError
	if !asStatus(err, &statusErr) || statusErr.StatusCode != http.StatusConflict {
		return false, false, err
	}

	existing, err := c.listNodeKinds(ctx)
	if err != nil {
		return false, false, err
	}
	var toCreate []NodeKind
	updated := false
	for _, kind := range kinds {
		if existing[kind.Name] {
			payload := map[string]map[string]map[string]string{
				"config": iconConfig(kind),
			}
			if err := c.request(ctx, http.MethodPut, "/api/v2/custom-nodes/"+url.PathEscape(kind.Name), payload, nil); err != nil {
				return false, updated, err
			}
			updated = true
			continue
		}
		toCreate = append(toCreate, kind)
	}
	if len(toCreate) > 0 {
		if err := c.createNodeKinds(ctx, toCreate); err != nil {
			return false, updated, err
		}
	}
	return len(toCreate) > 0, updated, nil
}

func (c *client) createNodeKinds(ctx context.Context, kinds []NodeKind) error {
	payload := map[string]map[string]map[string]map[string]string{
		"custom_types": {},
	}
	for _, kind := range kinds {
		payload["custom_types"][kind.Name] = iconConfig(kind)
	}
	return c.request(ctx, http.MethodPost, "/api/v2/custom-nodes", payload, nil)
}

type customNode struct {
	KindName string `json:"kindName"`
}

func (c *client) listNodeKinds(ctx context.Context) (map[string]bool, error) {
	var resp struct {
		Data []customNode `json:"data"`
	}
	if err := c.request(ctx, http.MethodGet, "/api/v2/custom-nodes", nil, &resp); err != nil {
		return nil, err
	}
	out := make(map[string]bool, len(resp.Data))
	for _, item := range resp.Data {
		out[item.KindName] = true
	}
	return out, nil
}

func iconConfig(kind NodeKind) map[string]map[string]string {
	return map[string]map[string]string{
		"icon": {
			"type":  "font-awesome",
			"name":  kind.Icon,
			"color": kind.Color,
		},
	}
}

func (c *client) registerSavedQueries(ctx context.Context, queries []SavedQuery) (int, int, int, error) {
	existing, err := c.listSavedQueries(ctx)
	if err != nil {
		return 0, 0, 0, err
	}
	existingByName := make(map[string]savedQuery, len(existing))
	for _, query := range existing {
		existingByName[query.Name] = query
	}

	created := 0
	updated := 0
	skipped := 0
	for _, query := range queries {
		if existingQuery, ok := existingByName[query.Name]; ok {
			if existingQuery.Query == query.Query {
				skipped++
				continue
			}
			if err := c.request(ctx, http.MethodDelete, fmt.Sprintf("/api/v2/saved-queries/%d", existingQuery.ID), nil, nil); err != nil {
				return created, updated, skipped, err
			}
			updated++
		}
		if err := c.request(ctx, http.MethodPost, "/api/v2/saved-queries", map[string]string{
			"name":        query.Name,
			"description": query.Description,
			"query":       query.Query,
		}, nil); err != nil {
			return created, updated, skipped, err
		}
		if _, ok := existingByName[query.Name]; !ok {
			created++
		}
	}
	return created, updated, skipped, nil
}

type savedQuery struct {
	ID    int    `json:"id"`
	Name  string `json:"name"`
	Query string `json:"query"`
}

func (c *client) listSavedQueries(ctx context.Context) ([]savedQuery, error) {
	var resp struct {
		Data []savedQuery `json:"data"`
	}
	if err := c.request(ctx, http.MethodGet, "/api/v2/saved-queries", nil, &resp); err != nil {
		return nil, err
	}
	sort.Slice(resp.Data, func(i, j int) bool {
		return resp.Data[i].Name < resp.Data[j].Name
	})
	return resp.Data, nil
}

func (c *client) removeCredsHoundQueries(ctx context.Context) (int, error) {
	queries, err := c.listSavedQueries(ctx)
	if err != nil {
		return 0, err
	}
	removed := 0
	for _, query := range queries {
		if !strings.HasPrefix(query.Name, savedQueryPrefix) {
			continue
		}
		if err := c.request(ctx, http.MethodDelete, fmt.Sprintf("/api/v2/saved-queries/%d", query.ID), nil, nil); err != nil {
			return removed, err
		}
		removed++
	}
	return removed, nil
}

func (c *client) removeSavedQueriesByName(ctx context.Context, names []string) (int, error) {
	if len(names) == 0 {
		return 0, nil
	}
	removeNames := make(map[string]bool, len(names))
	for _, name := range names {
		removeNames[name] = true
	}
	queries, err := c.listSavedQueries(ctx)
	if err != nil {
		return 0, err
	}
	removed := 0
	for _, query := range queries {
		if !removeNames[query.Name] {
			continue
		}
		if err := c.request(ctx, http.MethodDelete, fmt.Sprintf("/api/v2/saved-queries/%d", query.ID), nil, nil); err != nil {
			return removed, err
		}
		removed++
	}
	return removed, nil
}

func (c *client) request(ctx context.Context, method, path string, body any, out any) error {
	var reader io.Reader
	if body != nil {
		var b bytes.Buffer
		if err := json.NewEncoder(&b).Encode(body); err != nil {
			return err
		}
		reader = &b
	}

	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, reader)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return statusError{StatusCode: resp.StatusCode, Body: strings.TrimSpace(string(respBody))}
	}
	if out == nil || len(respBody) == 0 {
		return nil
	}
	if err := json.Unmarshal(respBody, out); err != nil {
		return fmt.Errorf("decode BloodHound response: %w", err)
	}
	return nil
}

type statusError struct {
	StatusCode int
	Body       string
}

func (e statusError) Error() string {
	if e.Body == "" {
		return fmt.Sprintf("BloodHound API returned HTTP %d", e.StatusCode)
	}
	return fmt.Sprintf("BloodHound API returned HTTP %d: %s", e.StatusCode, e.Body)
}

func asStatus(err error, target *statusError) bool {
	if err == nil {
		return false
	}
	if status, ok := err.(statusError); ok {
		*target = status
		return true
	}
	return false
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}
