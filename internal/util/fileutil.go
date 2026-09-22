package util

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"
)

// ReadFileBytes reads up to maxBytes from a file
func ReadFileBytes(path string, maxBytes int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	buf := make([]byte, maxBytes)
	n, err := f.Read(buf)
	if err != nil && err != io.EOF {
		return nil, err
	}
	return buf[:n], nil
}

// ReadFileLines reads file lines with a size limit
func ReadFileLines(path string, maxSize int64) ([]string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}

	if info.Size() > maxSize {
		return nil, fmt.Errorf("file size %d exceeds maximum allowed %d", info.Size(), maxSize)
	}

	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	// Set max token size to 1MB per line just in case
	const maxCapacity = 1024 * 1024
	buf := make([]byte, maxCapacity)
	scanner.Buffer(buf, maxCapacity)

	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return lines, nil
}

// IsBinaryFile checks the first few bytes for null characters
func IsBinaryFile(content []byte) bool {
	for _, b := range content {
		if b == 0 {
			return true
		}
	}
	return false
}

// GetSnippet extracts a code snippet with surrounding context lines (1-indexed line number)
func GetSnippet(lines []string, line int, context int) string {
	if line < 1 || line > len(lines) {
		return ""
	}

	start := line - 1 - context
	if start < 0 {
		start = 0
	}

	end := line - 1 + context
	if end >= len(lines) {
		end = len(lines) - 1
	}

	var snippet []string
	for i := start; i <= end; i++ {
		snippet = append(snippet, fmt.Sprintf("%d: %s", i+1, lines[i]))
	}

	return strings.Join(snippet, "\n")
}
