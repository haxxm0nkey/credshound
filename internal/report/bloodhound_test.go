package report

import (
	"bytes"
	"encoding/json"
	"regexp"
	"testing"

	"github.com/haxxm0nkey/credshound/internal/scanner"
)

func TestWriteBloodHound(t *testing.T) {
	findings := []scanner.Finding{
		{
			TemplateID:     "github",
			CredentialID:   "classic-personal-access-token",
			Origin:         scanner.OriginTemplate,
			Product:        "GitHub",
			Vendor:         "GitHub",
			Category:       "source_control",
			Credential:     "Classic personal access token",
			Source:         "file",
			Confidence:     "high",
			Location:       "/tmp/.git-credentials:1",
			CredentialType: "token",
			Evidence:       "ghp_****1234",
			URL:            "https://lolcreds.haxx.it/github#classic-personal-access-token",
		},
		{
			TemplateID:     "filesystem",
			CredentialID:   "interesting-location",
			Origin:         scanner.OriginObservation,
			Product:        "Filesystem",
			Credential:     "Interesting location",
			Source:         "file",
			Confidence:     "info",
			Location:       "/tmp/.git-credentials",
			CredentialType: "config_file",
			Evidence:       "path exists",
			References:     []string{"github"},
		},
	}

	var out bytes.Buffer
	if err := WriteBloodHound(&out, findings); err != nil {
		t.Fatal(err)
	}

	var payload bloodHoundPayload
	if err := json.Unmarshal(out.Bytes(), &payload); err != nil {
		t.Fatalf("expected valid JSON: %v\n%s", err, out.String())
	}
	if payload.Metadata.SourceKind != bloodHoundSourceKind {
		t.Fatalf("unexpected source kind %q", payload.Metadata.SourceKind)
	}
	if len(payload.Graph.Nodes) != 4 {
		t.Fatalf("expected host, exposure, credential, and service nodes, got %d: %+v", len(payload.Graph.Nodes), payload.Graph.Nodes)
	}
	if len(payload.Graph.Edges) != 3 {
		t.Fatalf("expected 3 edges, got %d: %+v", len(payload.Graph.Edges), payload.Graph.Edges)
	}

	if !hasBloodHoundNodeKind(payload.Graph.Nodes, bloodHoundKindHost) {
		t.Fatalf("expected host node kind, got %+v", payload.Graph.Nodes)
	}
	if !hasBloodHoundNodeKind(payload.Graph.Nodes, bloodHoundKindExposure) {
		t.Fatalf("expected exposure node kind, got %+v", payload.Graph.Nodes)
	}
	if !hasBloodHoundNodeKind(payload.Graph.Nodes, bloodHoundKindCredential) {
		t.Fatalf("expected credential node kind, got %+v", payload.Graph.Nodes)
	}
	if hasBloodHoundNodeKind(payload.Graph.Nodes, "Secret") || hasBloodHoundNodeKind(payload.Graph.Nodes, "Creds") || hasBloodHoundNodeKind(payload.Graph.Nodes, "CHCreds") {
		t.Fatalf("expected no built-in-looking credential node kind, got %+v", payload.Graph.Nodes)
	}
	if hasBloodHoundNodeKind(payload.Graph.Nodes, "CHObservation") {
		t.Fatalf("expected info observations to use exposure nodes, got %+v", payload.Graph.Nodes)
	}
	if !hasBloodHoundNodeKind(payload.Graph.Nodes, bloodHoundKindService) {
		t.Fatalf("expected service node kind, got %+v", payload.Graph.Nodes)
	}
	if !hasBloodHoundEdgeKind(payload.Graph.Edges, bloodHoundEdgeRevealsCredential) {
		t.Fatalf("expected RevealsCredential edge, got %+v", payload.Graph.Edges)
	}
	if !hasBloodHoundEdgeKind(payload.Graph.Edges, bloodHoundEdgeAuthenticatesTo) {
		t.Fatalf("expected AuthenticatesTo edge, got %+v", payload.Graph.Edges)
	}
	if !hasBloodHoundEdgeKind(payload.Graph.Edges, bloodHoundEdgeHasExposure) {
		t.Fatalf("expected HasExposure edge, got %+v", payload.Graph.Edges)
	}
	if !hasBloodHoundNodeProperty(payload.Graph.Nodes, "location", "/tmp/.git-credentials") {
		t.Fatalf("expected exposure location without line number, got %+v", payload.Graph.Nodes)
	}
	if !hasBloodHoundEdgeProperty(payload.Graph.Edges, "raw_location", "/tmp/.git-credentials:1") {
		t.Fatalf("expected reveal edge raw location with line number, got %+v", payload.Graph.Edges)
	}
	if !hasBloodHoundEdgeProperty(payload.Graph.Edges, "line", "1") {
		t.Fatalf("expected reveal edge line number, got %+v", payload.Graph.Edges)
	}
	if hasBloodHoundEdgeKind(payload.Graph.Edges, "CHDetectedBy") || hasBloodHoundNodeKind(payload.Graph.Nodes, "CHDetector") {
		t.Fatalf("expected no detector nodes or edges, got nodes=%+v edges=%+v", payload.Graph.Nodes, payload.Graph.Edges)
	}
	if hasBloodHoundNodeProperty(payload.Graph.Nodes, "objectid", "") {
		t.Fatalf("expected no reserved objectid node property, got %+v", payload.Graph.Nodes)
	}
	assertBloodHoundSchemaSafe(t, payload)
	for _, edge := range payload.Graph.Edges {
		if edge.Start.MatchBy != "id" || edge.End.MatchBy != "id" {
			t.Fatalf("expected id-matched endpoints, got %+v", edge)
		}
	}
}

func TestBloodHoundInfersUserProfile(t *testing.T) {
	payload := BloodHoundPayload([]scanner.Finding{
		{
			TemplateID:     "github",
			CredentialID:   "classic-personal-access-token",
			Origin:         scanner.OriginTemplate,
			Product:        "GitHub",
			Credential:     "Classic personal access token",
			Source:         "file",
			Confidence:     "high",
			Location:       "/Users/alice/.git-credentials:1",
			CredentialType: "token",
			Evidence:       "ghp_****1234",
		},
	})

	if !hasBloodHoundNodeKind(payload.Graph.Nodes, bloodHoundKindHost) {
		t.Fatalf("expected host node, got %+v", payload.Graph.Nodes)
	}
	if !hasBloodHoundNodeKind(payload.Graph.Nodes, bloodHoundKindLocalUser) {
		t.Fatalf("expected local user node, got %+v", payload.Graph.Nodes)
	}
	if hasBloodHoundNodeKind(payload.Graph.Nodes, "CHUserProfile") {
		t.Fatalf("expected user profile to be a local user/exposure property, got %+v", payload.Graph.Nodes)
	}
	if !hasBloodHoundNodeProperty(payload.Graph.Nodes, "profile_path", "/Users/alice") {
		t.Fatalf("expected /Users/alice profile path, got %+v", payload.Graph.Nodes)
	}
	if !hasBloodHoundEdgeKind(payload.Graph.Edges, bloodHoundEdgeHasLocalUser) {
		t.Fatalf("expected HasLocalUser edge, got %+v", payload.Graph.Edges)
	}
	if !hasBloodHoundEdgeKind(payload.Graph.Edges, bloodHoundEdgeHasExposure) {
		t.Fatalf("expected HasExposure edge, got %+v", payload.Graph.Edges)
	}
	if !hasBloodHoundEdgeKind(payload.Graph.Edges, bloodHoundEdgeRevealsCredential) {
		t.Fatalf("expected RevealsCredential edge, got %+v", payload.Graph.Edges)
	}
}

func TestBloodHoundGroupsFileLineFindingsUnderOneExposure(t *testing.T) {
	payload := BloodHoundPayload([]scanner.Finding{
		{
			TemplateID:        "github",
			CredentialID:      "classic-personal-access-token",
			Origin:            scanner.OriginTemplate,
			Product:           "GitHub",
			Source:            "file",
			Confidence:        "high",
			Location:          "/Users/alice/.zsh_history:143",
			CredentialType:    "token",
			Evidence:          "ghp_****1111",
			SecretFingerprint: "hmac-sha256:first",
		},
		{
			TemplateID:        "github",
			CredentialID:      "classic-personal-access-token",
			Origin:            scanner.OriginTemplate,
			Product:           "GitHub",
			Source:            "file",
			Confidence:        "high",
			Location:          "/Users/alice/.zsh_history:147",
			CredentialType:    "token",
			Evidence:          "ghp_****2222",
			SecretFingerprint: "hmac-sha256:second",
		},
	})

	if countBloodHoundNodesWithProperty(payload.Graph.Nodes, "location", "/Users/alice/.zsh_history") != 1 {
		t.Fatalf("expected one file exposure without line numbers, got %+v", payload.Graph.Nodes)
	}
	if hasBloodHoundNodeProperty(payload.Graph.Nodes, "location", "/Users/alice/.zsh_history:143") {
		t.Fatalf("expected no exposure keyed by line-specific path, got %+v", payload.Graph.Nodes)
	}
	if !hasBloodHoundEdgeProperty(payload.Graph.Edges, "line", "143") || !hasBloodHoundEdgeProperty(payload.Graph.Edges, "line", "147") {
		t.Fatalf("expected line numbers on reveal edges, got %+v", payload.Graph.Edges)
	}
}

func assertBloodHoundSchemaSafe(t *testing.T, payload bloodHoundPayload) {
	t.Helper()
	edgeKindPattern := regexp.MustCompile(`^[A-Za-z0-9_]+$`)
	for _, node := range payload.Graph.Nodes {
		if _, exists := node.Properties["objectid"]; exists {
			t.Fatalf("reserved objectid property found on node %+v", node)
		}
		for _, kind := range node.Kinds {
			if kind == "Secret" || kind == "Creds" {
				t.Fatalf("built-in-looking node kind found on node %+v", node)
			}
		}
	}
	for _, edge := range payload.Graph.Edges {
		if !edgeKindPattern.MatchString(edge.Kind) {
			t.Fatalf("edge kind is not OpenGraph safe: %+v", edge)
		}
	}
}

func hasBloodHoundNodeKind(nodes []bloodHoundNode, kind string) bool {
	for _, node := range nodes {
		for _, nodeKind := range node.Kinds {
			if nodeKind == kind {
				return true
			}
		}
	}
	return false
}

func hasBloodHoundNodeProperty(nodes []bloodHoundNode, key, value string) bool {
	for _, node := range nodes {
		got, ok := node.Properties[key]
		if ok && (value == "" || got == value) {
			return true
		}
	}
	return false
}

func countBloodHoundNodesWithProperty(nodes []bloodHoundNode, key, value string) int {
	count := 0
	for _, node := range nodes {
		got, ok := node.Properties[key]
		if ok && got == value {
			count++
		}
	}
	return count
}

func hasBloodHoundEdgeKind(edges []bloodHoundEdge, kind string) bool {
	for _, edge := range edges {
		if edge.Kind == kind {
			return true
		}
	}
	return false
}

func hasBloodHoundEdgeProperty(edges []bloodHoundEdge, key, value string) bool {
	for _, edge := range edges {
		got, ok := edge.Properties[key]
		if ok && (value == "" || got == value) {
			return true
		}
	}
	return false
}
