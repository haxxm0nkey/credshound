package templates

import (
	"fmt"

	"gopkg.in/yaml.v3"
)

type StringList []string

func (s *StringList) UnmarshalYAML(value *yaml.Node) error {
	switch value.Kind {
	case yaml.ScalarNode:
		if value.Value == "" {
			*s = nil
			return nil
		}
		*s = []string{value.Value}
		return nil
	case yaml.SequenceNode:
		out := make([]string, 0, len(value.Content))
		for _, item := range value.Content {
			if item.Kind != yaml.ScalarNode {
				return fmt.Errorf("expected string list item, got YAML kind %d", item.Kind)
			}
			out = append(out, item.Value)
		}
		*s = out
		return nil
	case yaml.MappingNode:
		*s = nil
		return nil
	default:
		*s = nil
		return nil
	}
}
