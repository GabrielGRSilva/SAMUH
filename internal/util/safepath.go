package util

import (
	"fmt"
	"path/filepath"
	"strings"
)

// ResolveSafePath resolves targetPath and ensures it's within basePath
func ResolveSafePath(basePath, targetPath string) (string, error) {
	absBase, err := filepath.Abs(basePath)
	if err != nil {
		return "", fmt.Errorf("failed to get absolute base path: %w", err)
	}

	evalBase, err := filepath.EvalSymlinks(absBase)
	if err != nil {
		evalBase = absBase // fallback
	}

	absTarget := targetPath
	if !filepath.IsAbs(targetPath) {
		absTarget = filepath.Join(evalBase, targetPath)
	}

	evalTarget, err := filepath.EvalSymlinks(absTarget)
	if err != nil {
		evalTarget = absTarget // fallback
	}

	// Clean paths
	cleanBase := filepath.Clean(evalBase)
	cleanTarget := filepath.Clean(evalTarget)

	if !strings.HasPrefix(cleanTarget, cleanBase+string(filepath.Separator)) && cleanTarget != cleanBase {
		return "", fmt.Errorf("path traversal attempt detected: %s is outside of %s", targetPath, basePath)
	}

	return cleanTarget, nil
}

// IsWithinDirectory checks if a path is safely within a base directory
func IsWithinDirectory(basePath, targetPath string) bool {
	_, err := ResolveSafePath(basePath, targetPath)
	return err == nil
}
