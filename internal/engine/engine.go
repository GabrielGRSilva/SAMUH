// Package engine provides the core scan orchestrator that coordinates file
// discovery, language analysis, and result aggregation for SAMUH.
package engine

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"samuh/internal/analyzer"
	"samuh/internal/rules"
	"samuh/internal/scanner"
)

// Options configures a scan operation.
type Options struct {
	// Path is the root directory to scan.
	Path string

	// Exclude is a list of glob patterns to exclude from scanning.
	Exclude []string

	// Languages filters scanning to specific language analyzers.
	// If empty, all registered analyzers are used.
	Languages []string

	// MinSeverity is the minimum severity level for reported findings.
	MinSeverity rules.Severity

	// MaxFileSize is the maximum file size in bytes to scan.
	MaxFileSize int64

	// Verbose enables detailed progress output during scanning.
	Verbose bool
}

// Engine orchestrates the scanning process by coordinating file discovery,
// running language analyzers concurrently, and aggregating findings.
type Engine struct {
	registry *analyzer.Registry
	opts     Options
}

// New creates a new scan Engine with the given analyzer registry and options.
func New(registry *analyzer.Registry, opts Options) *Engine {
	return &Engine{
		registry: registry,
		opts:     opts,
	}
}

// Run executes the scan and returns a complete ScanReport.
// It respects context cancellation for timeout support.
func (e *Engine) Run(ctx context.Context) (*rules.ScanReport, error) {
	start := time.Now()

	// Discover files
	scn := scanner.New(e.opts.Path, e.opts.Exclude, e.opts.MaxFileSize)
	files, err := scn.DiscoverFiles(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to discover files: %w", err)
	}

	if e.opts.Verbose {
		fmt.Fprintf(os.Stderr, "[verbose] Discovered %d file(s) to scan\n", len(files))
	}

	// Get analyzers, optionally filtering by language
	analyzers := e.getAnalyzers()

	if len(analyzers) == 0 {
		return nil, fmt.Errorf("no analyzers available for the specified languages")
	}

	if e.opts.Verbose {
		names := make([]string, len(analyzers))
		for i, a := range analyzers {
			names[i] = a.Name()
		}
		fmt.Fprintf(os.Stderr, "[verbose] Active analyzers: %s\n", strings.Join(names, ", "))
		fmt.Fprintf(os.Stderr, "[verbose] Worker pool size: %d\n", runtime.NumCPU())
	}

	// Run file-level analysis concurrently
	var allFindings []rules.Finding
	var mu sync.Mutex

	numWorkers := runtime.NumCPU()
	if numWorkers < 1 {
		numWorkers = 1
	}

	fileChan := make(chan *analyzer.FileContext, len(files))
	for _, f := range files {
		fileChan <- f
	}
	close(fileChan)

	var wg sync.WaitGroup
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for fc := range fileChan {
				select {
				case <-ctx.Done():
					return
				default:
				}

				ext := strings.ToLower(filepath.Ext(fc.Path))
				for _, a := range analyzers {
					if supportsExt(a, ext) {
						findings, err := a.Analyze(ctx, *fc)
						if err == nil && len(findings) > 0 {
							mu.Lock()
							allFindings = append(allFindings, findings...)
							mu.Unlock()
						}
					}
				}
			}
		}()
	}

	wg.Wait()

	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	// Run project-level analysis
	if e.opts.Verbose {
		fmt.Fprintf(os.Stderr, "[verbose] Running project-level analysis...\n")
	}
	for _, a := range analyzers {
		findings, err := a.AnalyzeProject(ctx, e.opts.Path)
		if err == nil && len(findings) > 0 {
			allFindings = append(allFindings, findings...)
			if e.opts.Verbose {
				fmt.Fprintf(os.Stderr, "[verbose] %s project analysis: %d finding(s)\n", a.Name(), len(findings))
			}
		}
	}

	if e.opts.Verbose {
		fmt.Fprintf(os.Stderr, "[verbose] Total raw findings before filtering: %d\n", len(allFindings))
		fmt.Fprintf(os.Stderr, "[verbose] Minimum severity filter: %s\n", e.opts.MinSeverity)
	}

	// Filter by minimum severity
	var filteredFindings []rules.Finding
	for _, f := range allFindings {
		if f.Severity.IsAtLeast(e.opts.MinSeverity) {
			filteredFindings = append(filteredFindings, f)
		}
	}

	if e.opts.Verbose {
		fmt.Fprintf(os.Stderr, "[verbose] Findings after severity filter: %d\n", len(filteredFindings))
	}

	// Sort by severity (critical first)
	sort.Slice(filteredFindings, func(i, j int) bool {
		return filteredFindings[i].Severity.Rank() > filteredFindings[j].Severity.Rank()
	})

	// Build summary
	summary := rules.NewReportSummary()
	languageSet := make(map[string]bool)
	for _, f := range filteredFindings {
		summary.BySeverity[f.Severity]++
		summary.ByOWASP[f.OWASP]++
		for _, n := range f.NIST {
			summary.ByNIST[n]++
		}
		summary.ByLanguage[f.Language]++
		summary.ByFile[f.FilePath]++
		languageSet[f.Language] = true
	}

	languages := make([]string, 0, len(languageSet))
	for lang := range languageSet {
		if lang != "" {
			languages = append(languages, lang)
		}
	}
	sort.Strings(languages)

	duration := time.Since(start)

	report := &rules.ScanReport{
		ProjectPath:    e.opts.Path,
		ScanTimestamp:  start.Format(time.RFC3339),
		ScanDuration:   fmt.Sprintf("%.2fs", duration.Seconds()),
		ScanDurationMs: duration.Milliseconds(),
		TotalFiles:     len(files),
		TotalFindings:  len(filteredFindings),
		Findings:       filteredFindings,
		Summary:        summary,
		Languages:      languages,
		ScannerVersion: "0.1.0",
	}

	return report, nil
}

// getAnalyzers returns the analyzers to use, filtered by language if specified.
func (e *Engine) getAnalyzers() []analyzer.Analyzer {
	all := e.registry.All()

	if len(e.opts.Languages) == 0 {
		return all
	}

	var filtered []analyzer.Analyzer
	for _, a := range all {
		for _, lang := range e.opts.Languages {
			if strings.EqualFold(a.Name(), lang) {
				filtered = append(filtered, a)
				break
			}
		}
	}
	return filtered
}

// supportsExt checks if an analyzer handles a given file extension.
func supportsExt(a analyzer.Analyzer, ext string) bool {
	ext = strings.ToLower(ext)
	for _, supported := range a.Extensions() {
		if strings.ToLower(supported) == ext {
			return true
		}
	}
	return false
}
