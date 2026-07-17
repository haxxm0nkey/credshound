package scanner

import (
	"context"
	"os"
	"strings"
)

func scanEnvironment(ctx context.Context, compiled []compiledCredential, opts Options) []Finding {
	var findings []Finding
	for _, item := range compiled {
		select {
		case <-ctx.Done():
			return findings
		default:
		}

		for _, location := range item.locations {
			if strings.ToLower(location.Type) != "environment" {
				continue
			}
			for _, name := range splitPathList(location.Path) {
				value, ok := os.LookupEnv(name)
				if !ok || strings.TrimSpace(value) == "" {
					continue
				}

				confidence := "high"
				evidence := value
				if len(item.patterns) > 0 {
					confidence = "medium"
					for _, re := range item.patterns {
						if match := re.FindString(value); match != "" {
							confidence = "high"
							evidence = match
							break
						}
					}
				}
				findings = append(findings, item.finding("env", confidence, name, evidence, opts))
			}
		}
	}
	return findings
}
