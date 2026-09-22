// Package analyzer defines the interface for language-specific security analyzers
// and provides a registry for discovering and managing them.
package analyzer

import (
	"context"
	"samuh/internal/rules"
)

// FileContext provides all necessary information about a file to be analyzed.
type FileContext struct {
	// Path is the absolute path to the file.
	Path string

	// RelativePath is the path relative to the project root.
	RelativePath string

	// Content is the file content as bytes.
	Content []byte

	// Lines is the file content split into lines for convenience.
	Lines []string

	// Language is the detected language of the file.
	Language string

	// Size is the file size in bytes.
	Size int64
}

// Analyzer is the interface that language-specific analyzers must implement.
// Each analyzer is responsible for detecting vulnerabilities in files of its
// supported language(s).
type Analyzer interface {
	// Name returns the human-readable name of this analyzer (e.g., "PHP").
	Name() string

	// Extensions returns the file extensions this analyzer handles
	// (e.g., []string{".php", ".phtml"}).
	Extensions() []string

	// Analyze scans a single file and returns any findings.
	// It must respect context cancellation for timeout support.
	Analyze(ctx context.Context, file FileContext) ([]rules.Finding, error)

	// AnalyzeProject performs project-level analysis (e.g., checking
	// package.json or composer.json for dependency vulnerabilities).
	// The projectRoot is the scanned directory path.
	// This is called once per scan, not per file.
	AnalyzeProject(ctx context.Context, projectRoot string) ([]rules.Finding, error)
}
