package templates

type Entry struct {
	ID          string       `yaml:"id"`
	Name        string       `yaml:"name"`
	Vendor      string       `yaml:"vendor"`
	Category    string       `yaml:"category"`
	Description string       `yaml:"description"`
	Credentials []Credential `yaml:"credentials"`
}

type Credential struct {
	ID          string      `yaml:"id"`
	Name        string      `yaml:"name"`
	Description string      `yaml:"description"`
	Type        string      `yaml:"type"`
	Nature      StringList  `yaml:"nature"`
	Sensitivity string      `yaml:"sensitivity"`
	Location    []Location  `yaml:"location"`
	LooksLike   []LooksLike `yaml:"looks_like"`
	Notes       StringList  `yaml:"notes"`
}

type Location struct {
	Type   string `yaml:"type"`
	Path   string `yaml:"path"`
	Detail string `yaml:"detail"`
}

type LooksLike struct {
	Example string `yaml:"example"`
	Pattern string `yaml:"pattern"`
	Detail  string `yaml:"detail"`
}
