package scanner

const (
	OriginTemplate    = "template"
	OriginBuiltin     = "builtin"
	OriginObservation = "observation"
)

type Finding struct {
	TemplateID        string   `json:"template_id"`
	CredentialID      string   `json:"credential_id"`
	Origin            string   `json:"origin"`
	Product           string   `json:"product"`
	Vendor            string   `json:"vendor,omitempty"`
	Category          string   `json:"category,omitempty"`
	Credential        string   `json:"credential"`
	Source            string   `json:"source"`
	Confidence        string   `json:"confidence"`
	Location          string   `json:"location"`
	CredentialType    string   `json:"credential_type"`
	Evidence          string   `json:"evidence"`
	SecretFingerprint string   `json:"secret_fingerprint,omitempty"`
	URL               string   `json:"url"`
	References        []string `json:"references,omitempty"`
}
