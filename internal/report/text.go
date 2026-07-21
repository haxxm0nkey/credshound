package report

import (
	"fmt"
	"io"
	"strings"

	"github.com/haxxm0nkey/credshound/internal/scanner"
)

type TextOptions struct {
	Color bool
}

func WriteText(w io.Writer, findings []scanner.Finding, opts TextOptions) error {
	for _, f := range findings {
		line := formatFinding(f, opts)
		if _, err := fmt.Fprintln(w, line); err != nil {
			return err
		}
	}
	return nil
}

func formatFinding(f scanner.Finding, opts TextOptions) string {
	template := f.TemplateID + ":" + f.CredentialID
	tail := f.URL
	if len(f.References) > 0 {
		if len(f.References) > 1 || tail == "" {
			tail = referencesText(f.References)
		}
	}
	if !opts.Color {
		if tail == "" {
			return fmt.Sprintf(
				"[%s] [%s] [%s] [%s] [%s] [%s]",
				template,
				f.Source,
				f.Confidence,
				f.Location,
				f.CredentialType,
				f.Evidence,
			)
		}
		return fmt.Sprintf(
			"[%s] [%s] [%s] [%s] [%s] [%s] [%s]",
			template,
			f.Source,
			f.Confidence,
			f.Location,
			f.CredentialType,
			f.Evidence,
			tail,
		)
	}

	if tail == "" {
		return fmt.Sprintf(
			"%s %s %s %s %s %s",
			bracket(template, magentaBold),
			bracket(f.Source, sourceColor(f.Source)),
			bracket(f.Confidence, confidenceColor(f.Confidence)),
			bracket(f.Location, pathColor),
			bracket(f.CredentialType, blueBold),
			bracket(f.Evidence, whiteBold),
		)
	}

	return fmt.Sprintf(
		"%s %s %s %s %s %s %s",
		bracket(template, magentaBold),
		bracket(f.Source, sourceColor(f.Source)),
		bracket(f.Confidence, confidenceColor(f.Confidence)),
		bracket(f.Location, pathColor),
		bracket(f.CredentialType, blueBold),
		bracket(f.Evidence, whiteBold),
		bracket(tail, linkBlue),
	)
}

func referencesText(references []string) string {
	if len(references) == 1 {
		return references[0]
	}
	return fmt.Sprintf("referenced by %d templates", len(references))
}

func bracket(value, color string) string {
	return colorize("["+value+"]", color)
}

func sourceColor(source string) string {
	switch strings.ToLower(source) {
	case "env":
		return greenBold
	case "file":
		return yellowBold
	case "registry":
		return blueBold
	case "proc":
		return cyanBright
	default:
		return cyanBright
	}
}

func confidenceColor(confidence string) string {
	switch strings.ToLower(confidence) {
	case "high":
		return redBold
	case "medium":
		return yellowBold
	case "low":
		return blueBold
	default:
		return cyanBright
	}
}

func colorize(value, color string) string {
	if value == "" || color == "" {
		return value
	}
	return color + value + reset
}

const (
	reset       = "\x1b[0m"
	magentaBold = "\x1b[1;95m"
	redBold     = "\x1b[1;91m"
	greenBold   = "\x1b[1;92m"
	yellowBold  = "\x1b[1;93m"
	blueBold    = "\x1b[1;94m"
	cyanBright  = "\x1b[96m"
	pathColor   = "\x1b[37m"
	whiteBold   = "\x1b[1;97m"
	linkBlue    = "\x1b[4;94m"
)
