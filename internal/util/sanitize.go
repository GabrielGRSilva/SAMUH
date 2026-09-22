package util

import (
	"path/filepath"
	"strings"
)

// SanitizeSnippet truncates code snippets safely and cleans non-printable characters
func SanitizeSnippet(code string, maxLen int) string {
	cleaned := strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r == '\t' {
			return r
		}
		if r < 32 || r == 127 {
			return -1
		}
		return r
	}, code)

	return TruncateString(cleaned, maxLen)
}

// SanitizeFilePath cleans file paths for display, ensuring no unexpected traversal elements
func SanitizeFilePath(path string) string {
	return filepath.Clean(path)
}

// TruncateString safely truncates a string to a max length
func TruncateString(s string, maxLen int) string {
	if maxLen <= 0 {
		return ""
	}
	if len(s) <= maxLen {
		return s
	}
	if maxLen <= 3 {
		return s[:maxLen]
	}
	return s[:maxLen-3] + "..."
}
