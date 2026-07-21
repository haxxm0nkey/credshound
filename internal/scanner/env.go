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

				findings = append(findings, environmentValueFinding(item, "env", name, value, opts))
			}
		}
	}
	return findings
}

func environmentValueFinding(item compiledCredential, source, location, value string, opts Options) Finding {
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
	return item.finding(source, confidence, location, evidence, opts)
}
