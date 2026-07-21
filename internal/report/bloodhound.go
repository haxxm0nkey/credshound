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
	bloodHoundKindHost       = "CHHost"
	bloodHoundKindLocalUser  = "CHLocalUser"
	bloodHoundKindExposure   = "CHExposure"
	bloodHoundKindCredential = "CHCredential"
	bloodHoundKindService    = "CHService"

	bloodHoundEdgeHasLocalUser      = "CHHasLocalUser"
	bloodHoundEdgeHasExposure       = "CHHasExposure"
	bloodHoundEdgeRevealsCredential = "CHRevealsCredential"
	bloodHoundEdgeAuthenticatesTo   = "CHAuthenticatesTo"
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
	Kind       string             `json:"kind"`
	Start      bloodHoundEndpoint `json:"start"`
	End        bloodHoundEndpoint `json:"end"`
	Properties map[string]string  `json:"properties,omitempty"`
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
		locationValue, line := findingLocationParts(finding)
		exposureID := bloodHoundExposureID(finding.Source, locationValue)
		exposureProperties := compactBloodHoundProperties(map[string]string{
			"name":        bloodHoundExposureName(finding.Source, locationValue),
			"displayname": bloodHoundExposureName(finding.Source, locationValue),
			"source":      finding.Source,
			"location":    locationValue,
		})

		if finding.Source == "file" {
			if profile, ok := inferUserProfile(locationValue); ok {
				localUserID := bloodHoundID("localuser", host.ID, profile.Username)

				addBloodHoundNode(&payload.Graph.Nodes, seenNodes, bloodHoundNode{
					ID:    localUserID,
					Kinds: []string{bloodHoundKindLocalUser},
					Properties: map[string]string{
						"name":         host.Name + "\\" + profile.Username,
						"displayname":  host.Name + "\\" + profile.Username,
						"username":     profile.Username,
						"hostname":     host.Name,
						"profile_path": profile.Path,
					},
				})
				exposureProperties["username"] = profile.Username
				exposureProperties["profile_path"] = profile.Path
				addBloodHoundEdge(&payload.Graph.Edges, seenEdges, bloodHoundEdgeHasLocalUser, host.ID, localUserID)
				addBloodHoundEdge(&payload.Graph.Edges, seenEdges, bloodHoundEdgeHasExposure, localUserID, exposureID)
			} else {
				addBloodHoundEdge(&payload.Graph.Edges, seenEdges, bloodHoundEdgeHasExposure, host.ID, exposureID)
			}
		} else {
			addBloodHoundEdge(&payload.Graph.Edges, seenEdges, bloodHoundEdgeHasExposure, host.ID, exposureID)
		}

		addBloodHoundNode(&payload.Graph.Nodes, seenNodes, bloodHoundNode{
			ID:         exposureID,
			Kinds:      []string{bloodHoundKindExposure},
			Properties: exposureProperties,
		})

		if isBloodHoundCredentialFinding(finding) {
			credentialID := bloodHoundCredentialID(finding)
			addBloodHoundNode(&payload.Graph.Nodes, seenNodes, bloodHoundNode{
				ID:    credentialID,
				Kinds: []string{bloodHoundKindCredential},
				Properties: compactBloodHoundProperties(map[string]string{
					"name":               bloodHoundCredentialName(finding),
					"displayname":        bloodHoundCredentialName(finding),
					"credential_type":    finding.CredentialType,
					"confidence":         finding.Confidence,
					"secret_fingerprint": finding.SecretFingerprint,
				}),
			})
			addBloodHoundEdgeWithProperties(&payload.Graph.Edges, seenEdges, bloodHoundEdgeRevealsCredential, exposureID, credentialID, bloodHoundFindingProperties(finding, line))
			if isBloodHoundServiceFinding(finding) {
				serviceID := bloodHoundServiceID(finding)
				addBloodHoundNode(&payload.Graph.Nodes, seenNodes, bloodHoundNode{
					ID:    serviceID,
					Kinds: []string{bloodHoundKindService},
					Properties: compactBloodHoundProperties(map[string]string{
						"name":        bloodHoundServiceName(finding),
						"displayname": bloodHoundServiceName(finding),
						"service_id":  bloodHoundServiceKey(finding),
						"vendor":      finding.Vendor,
						"category":    finding.Category,
						"url":         finding.URL,
					}),
				})
				addBloodHoundEdge(&payload.Graph.Edges, seenEdges, bloodHoundEdgeAuthenticatesTo, credentialID, serviceID)
			}
		}
	}
	return payload
}

func bloodHoundExposureID(source, location string) string {
	return bloodHoundID("exposure", source, location)
}

func bloodHoundCredentialID(finding scanner.Finding) string {
	if finding.SecretFingerprint != "" {
		return bloodHoundID("credential", finding.CredentialType, finding.SecretFingerprint)
	}
	return bloodHoundID("credential", finding.TemplateID, finding.CredentialID, finding.Source, finding.Location, finding.Evidence)
}

func bloodHoundCredentialName(finding scanner.Finding) string {
	name := finding.TemplateID + ":" + finding.CredentialID
	if strings.TrimSpace(finding.Product) != "" {
		name = strings.ToLower(strings.ReplaceAll(finding.Product, " ", "-")) + ":" + finding.CredentialID
	}
	return name
}

func bloodHoundExposureName(source, location string) string {
	if strings.TrimSpace(location) != "" {
		return location
	}
	return source
}

func bloodHoundFindingProperties(finding scanner.Finding, line string) map[string]string {
	return compactBloodHoundProperties(map[string]string{
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
		"raw_location":    finding.Location,
		"line":            line,
		"credential_type": finding.CredentialType,
		"evidence":        finding.Evidence,
		"url":             finding.URL,
		"references":      strings.Join(finding.References, ","),
		"reference_count": fmt.Sprintf("%d", len(finding.References)),
	})
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
	addBloodHoundEdgeWithProperties(edges, seen, kind, startID, endID, nil)
}

func addBloodHoundEdgeWithProperties(edges *[]bloodHoundEdge, seen map[string]bool, kind, startID, endID string, properties map[string]string) {
	key := kind + "\x00" + startID + "\x00" + endID
	if seen[key] {
		return
	}
	seen[key] = true
	*edges = append(*edges, bloodHoundEdge{
		Kind:       kind,
		Start:      bloodHoundEndpoint{Value: startID, MatchBy: "id"},
		End:        bloodHoundEndpoint{Value: endID, MatchBy: "id"},
		Properties: properties,
	})
}

func findingLocationParts(f scanner.Finding) (string, string) {
	if f.Source == "file" {
		return splitLocationLineForReport(f.Location)
	}
	return f.Location, ""
}

func isBloodHoundCredentialFinding(f scanner.Finding) bool {
	return !strings.EqualFold(f.Confidence, "info")
}

func isBloodHoundServiceFinding(f scanner.Finding) bool {
	if !isBloodHoundCredentialFinding(f) {
		return false
	}
	if f.TemplateID == "process" || strings.EqualFold(f.Product, "Process environment") {
		return false
	}
	return strings.TrimSpace(f.Product) != "" || (strings.TrimSpace(f.TemplateID) != "" && f.TemplateID != "filesystem")
}

func bloodHoundServiceID(f scanner.Finding) string {
	return bloodHoundID("service", bloodHoundServiceKey(f), f.Vendor, f.Category)
}

func bloodHoundServiceKey(f scanner.Finding) string {
	if f.TemplateID != "" && f.TemplateID != "filesystem" {
		return f.TemplateID
	}
	if f.Product != "" {
		return strings.ToLower(strings.ReplaceAll(f.Product, " ", "-"))
	}
	return "unknown"
}

func bloodHoundServiceName(f scanner.Finding) string {
	if strings.TrimSpace(f.Product) != "" {
		return strings.TrimSpace(f.Product)
	}
	return "Unknown service"
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
