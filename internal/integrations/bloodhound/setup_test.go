package bloodhound

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestRunRegistersIconsAndQueriesWithToken(t *testing.T) {
	var customNodesPosted bool
	var savedQueryPosts int
	var sawAuthorization bool

	withFakeHTTPClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "Bearer test-token" {
			sawAuthorization = true
		}
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/v2/custom-nodes":
			customNodesPosted = true
			var body struct {
				CustomTypes map[string]map[string]map[string]string `json:"custom_types"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode custom node payload: %v", err)
			}
			if len(body.CustomTypes) != len(NodeKinds) || body.CustomTypes["CHCredential"]["icon"]["name"] != "key" {
				t.Fatalf("unexpected custom node payload: %#v", body)
			}
			w.WriteHeader(http.StatusCreated)
		case r.Method == http.MethodGet && r.URL.Path == "/api/v2/saved-queries":
			writeJSON(t, w, map[string]any{
				"data": []map[string]any{
					{"id": 1, "name": SavedQueries[0].Name, "query": SavedQueries[0].Query},
				},
			})
		case r.Method == http.MethodPost && r.URL.Path == "/api/v2/saved-queries":
			savedQueryPosts++
			var body map[string]string
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode saved query payload: %v", err)
			}
			if !strings.HasPrefix(body["name"], savedQueryPrefix) || strings.TrimSpace(body["query"]) == "" {
				t.Fatalf("unexpected saved query payload: %#v", body)
			}
			w.WriteHeader(http.StatusCreated)
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	})

	result, err := Run(context.Background(), Options{
		Server:  "https://bloodhound.local",
		Token:   "test-token",
		Timeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !sawAuthorization || !customNodesPosted {
		t.Fatalf("expected authorized custom-node request, auth=%v customNodes=%v", sawAuthorization, customNodesPosted)
	}
	if !result.IconsCreated || result.IconsUpdated {
		t.Fatalf("unexpected icon result: %#v", result)
	}
	if result.QueriesCreated != len(SavedQueries)-1 || result.QueriesSkipped != 1 {
		t.Fatalf("unexpected query result: %#v", result)
	}
	if savedQueryPosts != len(SavedQueries)-1 {
		t.Fatalf("expected %d saved query posts, got %d", len(SavedQueries)-1, savedQueryPosts)
	}
}

func TestRunUpdatesStaleSavedQueries(t *testing.T) {
	var deletes []string
	var posts int

	withFakeHTTPClient(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v2/saved-queries":
			writeJSON(t, w, map[string]any{
				"data": []map[string]any{
					{"id": 42, "name": SavedQueries[0].Name, "query": "MATCH (old) RETURN old"},
				},
			})
		case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/api/v2/saved-queries/"):
			deletes = append(deletes, r.URL.Path)
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodPost && r.URL.Path == "/api/v2/saved-queries":
			posts++
			w.WriteHeader(http.StatusCreated)
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	})

	result, err := Run(context.Background(), Options{
		Server:  "https://bloodhound.local",
		Token:   "test-token",
		NoIcons: true,
		Timeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(deletes) != 1 || deletes[0] != "/api/v2/saved-queries/42" {
		t.Fatalf("expected stale query delete, got %#v", deletes)
	}
	if result.QueriesCreated != len(SavedQueries)-1 || result.QueriesUpdated != 1 || result.QueriesSkipped != 0 {
		t.Fatalf("unexpected query result: %#v", result)
	}
	if posts != len(SavedQueries) {
		t.Fatalf("expected %d saved query posts, got %d", len(SavedQueries), posts)
	}
}

func TestRunRemovesObsoleteSavedQueries(t *testing.T) {
	var deletes []string
	removedObsolete := false

	withFakeHTTPClient(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v2/saved-queries":
			if removedObsolete {
				writeJSON(t, w, map[string]any{"data": []map[string]any{}})
				return
			}
			writeJSON(t, w, map[string]any{"data": []map[string]any{
				{"id": 30, "name": "CredsHound - Evidence Table", "query": "MATCH (old) RETURN old"},
				{"id": 31, "name": "CredsHound - Node Kind Counts", "query": "MATCH (old) RETURN old"},
				{"id": 32, "name": "CredsHound - User Query", "query": "MATCH (keep) RETURN keep"},
			}})
		case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/api/v2/saved-queries/"):
			deletes = append(deletes, r.URL.Path)
			if len(deletes) == len(ObsoleteSavedQueryNames) {
				removedObsolete = true
			}
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodPost && r.URL.Path == "/api/v2/saved-queries":
			w.WriteHeader(http.StatusCreated)
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	})

	result, err := Run(context.Background(), Options{
		Server:  "https://bloodhound.local",
		Token:   "test-token",
		NoIcons: true,
		Timeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(deletes, ",") != "/api/v2/saved-queries/30,/api/v2/saved-queries/31" {
		t.Fatalf("expected only obsolete query deletes, got %#v", deletes)
	}
	if result.QueriesRemoved != 2 || result.QueriesCreated != len(SavedQueries) {
		t.Fatalf("unexpected query result: %#v", result)
	}
}

func TestRunUpdatesIconsWhenCustomNodeKindsAlreadyExist(t *testing.T) {
	var puts int

	withFakeHTTPClient(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/v2/custom-nodes":
			http.Error(w, "duplicate kind name", http.StatusConflict)
		case r.Method == http.MethodGet && r.URL.Path == "/api/v2/custom-nodes":
			data := make([]map[string]any, 0, len(NodeKinds))
			for _, kind := range NodeKinds {
				data = append(data, map[string]any{"kindName": kind.Name})
			}
			writeJSON(t, w, map[string]any{"data": data})
		case r.Method == http.MethodPut && strings.HasPrefix(r.URL.Path, "/api/v2/custom-nodes/"):
			puts++
			var body struct {
				Config map[string]map[string]string `json:"config"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode update payload: %v", err)
			}
			if body.Config["icon"]["type"] != "font-awesome" {
				t.Fatalf("unexpected update payload: %#v", body)
			}
			w.WriteHeader(http.StatusOK)
		case r.Method == http.MethodGet && r.URL.Path == "/api/v2/saved-queries":
			writeJSON(t, w, map[string]any{"data": []map[string]any{}})
		case r.Method == http.MethodPost && r.URL.Path == "/api/v2/saved-queries":
			w.WriteHeader(http.StatusCreated)
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	})

	result, err := Run(context.Background(), Options{
		Server:  "https://bloodhound.local",
		Token:   "test-token",
		Timeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	if puts != len(NodeKinds) {
		t.Fatalf("expected %d custom node updates, got %d", len(NodeKinds), puts)
	}
	if result.IconsCreated || !result.IconsUpdated {
		t.Fatalf("unexpected icon result: %#v", result)
	}
}

func TestRunCreatesMissingIconsAfterPartialConflict(t *testing.T) {
	var creates int
	var puts int

	withFakeHTTPClient(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/v2/custom-nodes":
			creates++
			if creates == 1 {
				http.Error(w, "duplicate kind name", http.StatusConflict)
				return
			}
			var body struct {
				CustomTypes map[string]map[string]map[string]string `json:"custom_types"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode create payload: %v", err)
			}
			if len(body.CustomTypes) != len(NodeKinds)-1 || body.CustomTypes["CHService"]["icon"]["name"] != "cube" {
				t.Fatalf("unexpected missing-kind create payload: %#v", body)
			}
			w.WriteHeader(http.StatusCreated)
		case r.Method == http.MethodGet && r.URL.Path == "/api/v2/custom-nodes":
			writeJSON(t, w, map[string]any{"data": []map[string]any{
				{"kindName": "CHHost"},
			}})
		case r.Method == http.MethodPut && strings.HasPrefix(r.URL.Path, "/api/v2/custom-nodes/"):
			puts++
			w.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	})

	result, err := Run(context.Background(), Options{
		Server:    "https://bloodhound.local",
		Token:     "test-token",
		NoQueries: true,
		Timeout:   time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	if creates != 2 || puts != 1 {
		t.Fatalf("unexpected icon API calls: creates=%d puts=%d", creates, puts)
	}
	if !result.IconsCreated || !result.IconsUpdated {
		t.Fatalf("unexpected icon result: %#v", result)
	}
}

func TestRunCanResetCredsHoundSavedQueries(t *testing.T) {
	var deletes []string
	deleted := false

	withFakeHTTPClient(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v2/saved-queries":
			if deleted {
				writeJSON(t, w, map[string]any{"data": []map[string]any{
					{"id": 11, "name": "Other Query", "query": "MATCH (n) RETURN n"},
				}})
				return
			}
			writeJSON(t, w, map[string]any{
				"data": []map[string]any{
					{"id": 10, "name": SavedQueries[0].Name, "query": SavedQueries[0].Query},
					{"id": 11, "name": "Other Query", "query": "MATCH (n) RETURN n"},
				},
			})
		case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/api/v2/saved-queries/"):
			deletes = append(deletes, r.URL.Path)
			deleted = true
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodPost && r.URL.Path == "/api/v2/saved-queries":
			w.WriteHeader(http.StatusCreated)
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	})

	result, err := Run(context.Background(), Options{
		Server:       "https://bloodhound.local",
		Token:        "test-token",
		NoIcons:      true,
		ResetQueries: true,
		Timeout:      time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(deletes) != 1 || deletes[0] != "/api/v2/saved-queries/10" {
		t.Fatalf("expected only CredsHound query delete, got %#v", deletes)
	}
	if result.QueriesRemoved != 1 || result.QueriesCreated != len(SavedQueries) || result.QueriesSkipped != 0 {
		t.Fatalf("unexpected query result: %#v", result)
	}
}

func TestSavedQueriesReturnGraphPathsForBloodHoundUI(t *testing.T) {
	for _, query := range SavedQueries {
		if !strings.Contains(query.Query, "RETURN p") {
			t.Fatalf("expected saved query %q to return graph paths, got:\n%s", query.Name, query.Query)
		}
		returnClause := query.Query[strings.LastIndex(query.Query, "RETURN "):]
		if strings.Contains(returnClause, " AS ") {
			t.Fatalf("expected saved query %q to avoid table-style scalar returns, got:\n%s", query.Name, query.Query)
		}
	}
}

func TestRunRequiresAuthentication(t *testing.T) {
	_, err := Run(context.Background(), Options{
		Server: "http://127.0.0.1:1",
	})
	if err == nil || !strings.Contains(err.Error(), "provide either -token or -username/-password") {
		t.Fatalf("expected auth error, got %v", err)
	}
}

func writeJSON(t *testing.T, w http.ResponseWriter, value any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(value); err != nil {
		t.Fatalf("write json: %v", err)
	}
}

func withFakeHTTPClient(t *testing.T, handler func(http.ResponseWriter, *http.Request)) {
	t.Helper()
	original := newHTTPClient
	newHTTPClient = func(time.Duration, http.RoundTripper) *http.Client {
		return &http.Client{
			Transport: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
				rec := &responseRecorder{
					header: make(http.Header),
					code:   http.StatusOK,
				}
				handler(rec, req)
				return &http.Response{
					StatusCode: rec.code,
					Header:     rec.header,
					Body:       io.NopCloser(strings.NewReader(rec.body.String())),
					Request:    req,
				}, nil
			}),
		}
	}
	t.Cleanup(func() {
		newHTTPClient = original
	})
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

type responseRecorder struct {
	header http.Header
	body   strings.Builder
	code   int
}

func (r *responseRecorder) Header() http.Header {
	return r.header
}

func (r *responseRecorder) Write(data []byte) (int, error) {
	return r.body.Write(data)
}

func (r *responseRecorder) WriteHeader(statusCode int) {
	r.code = statusCode
}
