package report

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"

	"github.com/haxxm0nkey/credshound/internal/scanner"
)

const bloodHoundSourceKind = "CredsHound"

const (
	bloodHoundKindHost        = "CHHost"
	bloodHoundKindLocation    = "CHLocation"
	bloodHoundKindLocalUser   = "CHLocalUser"
	bloodHoundKindUserProfile = "CHUserProfile"
	bloodHoundKindCreds       = "CHCreds"
	bloodHoundKindObservation = "CHObservation"
	bloodHoundKindProduct     = "CHProduct"

	bloodHoundEdgeContainsLocation = "CHContainsLocation"
	bloodHoundEdgeContainsCreds    = "CHContainsCreds"
	bloodHoundEdgeMayAuthenticate  = "CHMayAuthenticateTo"
	bloodHoundEdgeHasLocalUser     = "CHHasLocalUser"
	bloodHoundEdgeHasUserProfile   = "CHHasUserProfile"
)

type bloodHoundPayload struct {
	Graph    bloodHoundGraph    `json:"graph"`
	Metadata bloodHoundMetadata `json:"metadata"`
}

type bloodHoundGraph struct {
	Nodes []bloodHoundNode `json:"nodes"`
	Edges []bloodHoundEdge `json:"edges"`
}

type bloodHoundMetadata struct {
	SourceKind string `json:"source_kind"`
}

type bloodHoundNode struct {
	ID         string            `json:"id"`
	Kinds      []string          `json:"kinds"`
	Properties map[string]string `json:"properties"`
}

type bloodHoundEdge struct {
	Kind  string             `json:"kind"`
	Start bloodHoundEndpoint `json:"start"`
	End   bloodHoundEndpoint `json:"end"`
}

type bloodHoundEndpoint struct {
	Value   string `json:"value"`
	MatchBy string `json:"match_by"`
}

func WriteBloodHound(w io.Writer, findings []scanner.Finding) error {
	payload := BloodHoundPayload(findings)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(payload)
}

func BloodHoundPayload(findings []scanner.Finding) bloodHoundPayload {
	payload := bloodHoundPayload{
		Metadata: bloodHoundMetadata{SourceKind: bloodHoundSourceKind},
	}

	seenNodes := make(map[string]bool)
	seenEdges := make(map[string]bool)
	host := bloodHoundHost()
	addBloodHoundNode(&payload.Graph.Nodes, seenNodes, bloodHoundNode{
		ID:    host.ID,
		Kinds: []string{bloodHoundKindHost},
		Properties: map[string]string{
			"name":        host.Name,
			"displayname": host.Name,
			"hostname":    host.Name,
			"os":          host.OS,
		},
	})

	for _, finding := range findings {
		locationValue := findingLocationValue(finding)
		locationID := bloodHoundID("location", finding.Source, locationValue)
		findingID := bloodHoundID("finding", finding.TemplateID, finding.CredentialID, finding.Source, finding.Location, finding.Evidence)

		addBloodHoundNode(&payload.Graph.Nodes, seenNodes, bloodHoundNode{
			ID:    locationID,
			Kinds: []string{bloodHoundKindLocation},
			Properties: map[string]string{
				"name":        locationValue,
				"displayname": locationValue,
				"source":      finding.Source,
				"location":    locationValue,
			},
		})

		if finding.Source == "file" {
			if profile, ok := inferUserProfile(locationValue); ok {
				localUserID := bloodHoundID("localuser", host.ID, profile.Username)
				profileID := bloodHoundID("profile", host.ID, profile.Path)

				addBloodHoundNode(&payload.Graph.Nodes, seenNodes, bloodHoundNode{
					ID:    localUserID,
					Kinds: []string{bloodHoundKindLocalUser},
					Properties: map[string]string{
						"name":        host.Name + "\\" + profile.Username,
						"displayname": host.Name + "\\" + profile.Username,
						"username":    profile.Username,
						"hostname":    host.Name,
					},
				})
				addBloodHoundNode(&payload.Graph.Nodes, seenNodes, bloodHoundNode{
					ID:    profileID,
					Kinds: []string{bloodHoundKindUserProfile},
					Properties: map[string]string{
						"name":        profile.Path,
						"displayname": profile.Path,
						"path":        profile.Path,
						"username":    profile.Username,
						"hostname":    host.Name,
					},
				})
				addBloodHoundEdge(&payload.Graph.Edges, seenEdges, bloodHoundEdgeHasLocalUser, host.ID, localUserID)
				addBloodHoundEdge(&payload.Graph.Edges, seenEdges, bloodHoundEdgeHasUserProfile, localUserID, profileID)
				addBloodHoundEdge(&payload.Graph.Edges, seenEdges, bloodHoundEdgeContainsLocation, profileID, locationID)
			} else {
				addBloodHoundEdge(&payload.Graph.Edges, seenEdges, bloodHoundEdgeContainsLocation, host.ID, locationID)
			}
		} else {
			addBloodHoundEdge(&payload.Graph.Edges, seenEdges, bloodHoundEdgeContainsLocation, host.ID, locationID)
		}

		addBloodHoundNode(&payload.Graph.Nodes, seenNodes, bloodHoundNode{
			ID:    findingID,
			Kinds: bloodHoundFindingKinds(finding),
			Properties: compactBloodHoundProperties(map[string]string{
				"name":            bloodHoundFindingName(finding),
				"displayname":     bloodHoundFindingName(finding),
				"template_id":     finding.TemplateID,
				"credential_id":   finding.CredentialID,
				"detector_id":     finding.TemplateID + ":" + finding.CredentialID,
				"detector_name":   finding.Credential,
				"origin":          finding.Origin,
				"product":         finding.Product,
				"vendor":          finding.Vendor,
				"category":        finding.Category,
				"credential":      finding.Credential,
				"source":          finding.Source,
				"confidence":      finding.Confidence,
				"location":        finding.Location,
				"credential_type": finding.CredentialType,
				"evidence":        finding.Evidence,
				"url":             finding.URL,
				"references":      strings.Join(finding.References, ","),
				"reference_count": fmt.Sprintf("%d", len(finding.References)),
			}),
		})

		addBloodHoundEdge(&payload.Graph.Edges, seenEdges, bloodHoundEdgeContainsCreds, locationID, findingID)
		if isBloodHoundCredsFinding(finding) {
			productID := bloodHoundProductID(finding)
			addBloodHoundNode(&payload.Graph.Nodes, seenNodes, bloodHoundNode{
				ID:    productID,
				Kinds: []string{bloodHoundKindProduct},
				Properties: compactBloodHoundProperties(map[string]string{
					"name":        bloodHoundProductName(finding),
					"displayname": bloodHoundProductName(finding),
					"product_id":  bloodHoundProductKey(finding),
					"vendor":      finding.Vendor,
					"category":    finding.Category,
					"url":         finding.URL,
				}),
			})
			addBloodHoundEdge(&payload.Graph.Edges, seenEdges, bloodHoundEdgeMayAuthenticate, findingID, productID)
		}
	}
	return payload
}

type bloodHoundHostContext struct {
	ID   string
	Name string
	OS   string
}

type userProfileContext struct {
	Username string
	Path     string
}

func bloodHoundHost() bloodHoundHostContext {
	hostname, err := os.Hostname()
	if err != nil || strings.TrimSpace(hostname) == "" {
		hostname = "unknown-host"
	}
	hostname = strings.TrimSpace(hostname)
	return bloodHoundHostContext{
		ID:   bloodHoundID("host", runtime.GOOS, hostname),
		Name: hostname,
		OS:   runtime.GOOS,
	}
}

func inferUserProfile(location string) (userProfileContext, bool) {
	normalized := strings.ReplaceAll(location, "\\", "/")
	parts := strings.Split(normalized, "/")
	for i := 0; i+1 < len(parts); i++ {
		if !isUserProfileRoot(parts[i]) || !isSupportedProfileRootPosition(parts, i) {
			continue
		}
		username := strings.TrimSpace(parts[i+1])
		if !validProfileUsername(username) {
			continue
		}
		return userProfileContext{
			Username: username,
			Path:     strings.Join(parts[:i+2], "/"),
		}, true
	}
	return userProfileContext{}, false
}

func isUserProfileRoot(segment string) bool {
	switch strings.ToLower(segment) {
	case "users", "home":
		return true
	default:
		return false
	}
}

func isSupportedProfileRootPosition(parts []string, index int) bool {
	if index != 1 || len(parts) < 3 {
		return false
	}
	return parts[0] == "" || strings.HasSuffix(parts[0], ":")
}

func validProfileUsername(username string) bool {
	if username == "" || username == "." || username == ".." {
		return false
	}
	switch strings.ToLower(username) {
	case "all users", "default", "default user", "public", "shared":
		return false
	default:
		return true
	}
}

func addBloodHoundNode(nodes *[]bloodHoundNode, seen map[string]bool, node bloodHoundNode) {
	if seen[node.ID] {
		return
	}
	seen[node.ID] = true
	*nodes = append(*nodes, node)
}

func addBloodHoundEdge(edges *[]bloodHoundEdge, seen map[string]bool, kind, startID, endID string) {
	key := kind + "\x00" + startID + "\x00" + endID
	if seen[key] {
		return
	}
	seen[key] = true
	*edges = append(*edges, bloodHoundEdge{
		Kind:  kind,
		Start: bloodHoundEndpoint{Value: startID, MatchBy: "id"},
		End:   bloodHoundEndpoint{Value: endID, MatchBy: "id"},
	})
}

func bloodHoundFindingKinds(f scanner.Finding) []string {
	if strings.EqualFold(f.Confidence, "info") || f.Origin == scanner.OriginObservation {
		return []string{bloodHoundKindObservation}
	}
	return []string{bloodHoundKindCreds}
}

func bloodHoundFindingName(f scanner.Finding) string {
	id := f.TemplateID + ":" + f.CredentialID
	if f.Location == "" {
		return id
	}
	return id + " @ " + f.Location
}

func findingLocationValue(f scanner.Finding) string {
	if f.Source == "file" {
		location, _ := splitLocationLineForReport(f.Location)
		return location
	}
	return f.Location
}

func isBloodHoundCredsFinding(f scanner.Finding) bool {
	return !strings.EqualFold(f.Confidence, "info") && f.Origin != scanner.OriginObservation
}

func bloodHoundProductID(f scanner.Finding) string {
	return bloodHoundID("product", bloodHoundProductKey(f), f.Vendor, f.Category)
}

func bloodHoundProductKey(f scanner.Finding) string {
	if f.TemplateID != "" && f.TemplateID != "filesystem" {
		return f.TemplateID
	}
	if f.Product != "" {
		return strings.ToLower(strings.ReplaceAll(f.Product, " ", "-"))
	}
	return "unknown"
}

func bloodHoundProductName(f scanner.Finding) string {
	if strings.TrimSpace(f.Product) != "" {
		return strings.TrimSpace(f.Product)
	}
	return "Unknown product"
}

func compactBloodHoundProperties(properties map[string]string) map[string]string {
	for key, value := range properties {
		if strings.TrimSpace(value) == "" {
			delete(properties, key)
		}
	}
	return properties
}

func splitLocationLineForReport(location string) (string, string) {
	idx := strings.LastIndex(location, ":")
	if idx < 0 || idx == len(location)-1 {
		return location, ""
	}
	line := location[idx+1:]
	for _, r := range line {
		if r < '0' || r > '9' {
			return location, ""
		}
	}
	return location[:idx], line
}

func bloodHoundID(parts ...string) string {
	h := sha256.New()
	for _, part := range parts {
		_, _ = h.Write([]byte(part))
		_, _ = h.Write([]byte{0})
	}
	sum := hex.EncodeToString(h.Sum(nil))
	return "credshound-" + parts[0] + "-" + sum[:24]
}
