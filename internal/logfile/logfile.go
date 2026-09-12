// Package logfile sends a copy of the log to a file, alongside the console.
//
// Both, not either. The console is what an IDE shows and what somebody watching a terminal
// reads; the file is what a log shipper can tail after they have gone home. Choosing
// between them loses one of those.
package logfile

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// DirVar names the environment variable holding the directory. A directory rather than a
// file path, so every service in the stack writes into one place and a shipper has one
// thing to watch. Set it to nothing to turn the file off.
const DirVar = "MCP_LOG_DIR"

// DefaultDir is used when the variable is unset, so this works for somebody who has
// configured nothing.
const DefaultDir = "~/mcp-logs"

// Writer returns where the log should go, and the file to close if one was opened.
//
// A directory that cannot be written is reported and then let go: a service that refuses to
// start because it could not open a log file has turned an inconvenience into an outage.
// The caller keeps the console either way.
//
// There is no rotation here. Adding it means a dependency, and these two write far less
// than the Java services do — but a process left running for weeks will grow a large file.
func Writer(name string) (io.Writer, io.Closer, error) {
	dir, set := os.LookupEnv(DirVar)
	if !set {
		dir = DefaultDir
	}
	if dir == "" {
		return os.Stdout, nil, nil
	}

	dir = expand(dir)

	if err := os.MkdirAll(dir, 0o755); err != nil {
		return os.Stdout, nil, fmt.Errorf("log directory %s: %w", dir, err)
	}

	path := filepath.Join(dir, name+".log")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return os.Stdout, nil, fmt.Errorf("log file %s: %w", path, err)
	}

	return io.MultiWriter(os.Stdout, file), file, nil
}

// expand resolves a leading ~, which a shell would have done and an IDE's run
// configuration will not.
func expand(dir string) string {
	if dir != "~" && !strings.HasPrefix(dir, "~/") {
		return dir
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return dir
	}
	if dir == "~" {
		return home
	}
	return filepath.Join(home, dir[2:])
}
