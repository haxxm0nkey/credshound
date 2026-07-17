//go:build !windows

package scanner

import "context"

func scanRegistry(ctx context.Context, compiled []compiledCredential, opts Options) ([]Finding, error) {
	return nil, nil
}
