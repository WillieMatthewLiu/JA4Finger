package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/nextinfra/ja4finger/engine"
)

var (
	runLiveMode = engine.RunLive
	runPCAPMode = engine.RunPCAP
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	if err := runWithContext(ctx, os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string) error {
	return runWithContext(context.Background(), args, io.Discard, io.Discard)
}

func runWithContext(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return errors.New("missing subcommand: live or pcap")
	}

	switch args[0] {
	case "live":
		parsed, err := parseLiveFlags(args[1:])
		if err != nil {
			return err
		}
		return runLiveMode(ctx, parsed.value, stdout, stderr, parsed.debugHashInputs, parsed.logFile)
	case "pcap":
		parsed, err := parseCommandFlags("pcap", args[1:], "file", "f", "path to the PCAP file to analyze")
		if err != nil {
			return err
		}
		return runPCAPMode(ctx, parsed.value, stdout, stderr, parsed.debugHashInputs, parsed.logFile)
	default:
		return fmt.Errorf("unknown subcommand %q", args[0])
	}
}

type commandFlags struct {
	value           string
	debugHashInputs bool
	logFile         string
}

func parseLiveFlags(args []string) (*commandFlags, error) {
	fs := flag.NewFlagSet("live", flag.ContinueOnError)
	longVal := fs.String("interface", "", "name of the network interface to capture on")
	shortVal := fs.String("i", "", "short alias for --interface")
	configPath := fs.String("config", "", "path to a YAML config file containing live.interface")
	debugHashInputs := fs.Bool("debug-hash-inputs", false, "include JA4 pre-hash input strings in output")
	logFile := fs.String("log-file", "", "append JSONL results to this file; defaults to logs/yyyyMMdd-ja4finger-<mode>.log")
	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	if leftovers := fs.Args(); len(leftovers) > 0 {
		return nil, fmt.Errorf("live subcommand does not accept positional arguments: %s", strings.Join(leftovers, " "))
	}

	value := strings.TrimSpace(*longVal)
	if value == "" {
		value = strings.TrimSpace(*shortVal)
	}
	if value == "" {
		var err error
		value, err = loadLiveInterfaceFromConfig(strings.TrimSpace(*configPath))
		if err != nil {
			return nil, err
		}
	}
	if value == "" {
		return nil, errors.New("live subcommand requires --interface or --config with live.interface")
	}

	resolvedLogFile := strings.TrimSpace(*logFile)
	if resolvedLogFile == "" {
		resolvedLogFile = defaultLogFilePath("live", time.Now())
	}
	return &commandFlags{
		value:           value,
		debugHashInputs: *debugHashInputs,
		logFile:         resolvedLogFile,
	}, nil
}

func parseCommandFlags(subcommand string, args []string, longName, shortName, description string) (*commandFlags, error) {
	fs := flag.NewFlagSet(subcommand, flag.ContinueOnError)
	longVal := fs.String(longName, "", description)
	shortVal := fs.String(shortName, "", fmt.Sprintf("short alias for --%s", longName))
	debugHashInputs := fs.Bool("debug-hash-inputs", false, "include JA4 pre-hash input strings in output")
	logFile := fs.String("log-file", "", "append JSONL results to this file; defaults to logs/yyyyMMdd-ja4finger-<mode>.log")
	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	if leftovers := fs.Args(); len(leftovers) > 0 {
		return nil, fmt.Errorf("%s subcommand does not accept positional arguments: %s", subcommand, strings.Join(leftovers, " "))
	}
	value := strings.TrimSpace(*longVal)
	if value == "" {
		value = strings.TrimSpace(*shortVal)
	}
	if value == "" {
		return nil, fmt.Errorf("%s subcommand requires --%s", subcommand, longName)
	}
	resolvedLogFile := strings.TrimSpace(*logFile)
	if resolvedLogFile == "" {
		resolvedLogFile = defaultLogFilePath(subcommand, time.Now())
	}
	return &commandFlags{
		value:           value,
		debugHashInputs: *debugHashInputs,
		logFile:         resolvedLogFile,
	}, nil
}

func defaultLogFilePath(subcommand string, now time.Time) string {
	return filepath.Join("logs", now.Format("20060102")+"-ja4finger-"+subcommand+".log")
}

func loadLiveInterfaceFromConfig(path string) (string, error) {
	if path == "" {
		return "", nil
	}

	file, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("opening config file %q: %w", path, err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	inLive := false
	for lineNo := 1; scanner.Scan(); lineNo++ {
		raw := scanner.Text()
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		indent := len(raw) - len(strings.TrimLeft(raw, " "))
		if indent == 0 {
			inLive = false
			if strings.Contains(trimmed, ": ") {
				return "", fmt.Errorf("config file %q: root entries must be sections, got line %d", path, lineNo)
			}
			if trimmed != "live:" {
				continue
			}
			inLive = true
			continue
		}

		if !inLive {
			continue
		}
		if !strings.Contains(trimmed, ":") {
			return "", fmt.Errorf("config file %q: invalid YAML near line %d", path, lineNo)
		}
		key, value, found := strings.Cut(trimmed, ":")
		if !found {
			return "", fmt.Errorf("config file %q: invalid YAML near line %d", path, lineNo)
		}
		if strings.TrimSpace(key) != "interface" {
			continue
		}
		value = strings.TrimSpace(value)
		if value == "" {
			return "", fmt.Errorf("config file %q: live.interface must not be empty", path)
		}
		return value, nil
	}
	if err := scanner.Err(); err != nil {
		return "", fmt.Errorf("reading config file %q: %w", path, err)
	}
	return "", fmt.Errorf("config file %q: missing live.interface", path)
}
