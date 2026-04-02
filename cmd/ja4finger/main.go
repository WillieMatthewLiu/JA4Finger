package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
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
		return runLiveMode(ctx, parsed.value, stdout, stderr, parsed.debugHashInputs, parsed.logFile, parsed.liveOptions)
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
	liveOptions     engine.LiveOptions
}

type liveConfig struct {
	Interface     string
	ExcludeSrcIPs []string
	ExcludeDstIPs []string
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

	config, err := loadLiveConfig(strings.TrimSpace(*configPath))
	if err != nil {
		return nil, err
	}
	value := strings.TrimSpace(*longVal)
	if value == "" {
		value = strings.TrimSpace(*shortVal)
	}
	if value == "" {
		value = config.Interface
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
		liveOptions: engine.LiveOptions{
			ExcludeSrcIPs: append([]string(nil), config.ExcludeSrcIPs...),
			ExcludeDstIPs: append([]string(nil), config.ExcludeDstIPs...),
		},
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

func loadLiveConfig(path string) (*liveConfig, error) {
	config := &liveConfig{}
	if path == "" {
		return config, nil
	}

	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening config file %q: %w", path, err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	inLive := false
	currentList := ""
	for lineNo := 1; scanner.Scan(); lineNo++ {
		raw := scanner.Text()
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		indent := len(raw) - len(strings.TrimLeft(raw, " "))
		if indent == 0 {
			inLive = false
			currentList = ""
			if strings.Contains(trimmed, ": ") {
				return nil, fmt.Errorf("config file %q: root entries must be sections, got line %d", path, lineNo)
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
		if strings.HasPrefix(trimmed, "- ") {
			if currentList == "" {
				return nil, fmt.Errorf("config file %q: invalid YAML near line %d", path, lineNo)
			}
			item := strings.TrimSpace(strings.TrimPrefix(trimmed, "- "))
			if item == "" {
				return nil, fmt.Errorf("config file %q: empty list item near line %d", path, lineNo)
			}
			switch currentList {
			case "exclude_src_ips":
				config.ExcludeSrcIPs = append(config.ExcludeSrcIPs, item)
			case "exclude_dst_ips":
				config.ExcludeDstIPs = append(config.ExcludeDstIPs, item)
			}
			continue
		}
		if !strings.Contains(trimmed, ":") {
			return nil, fmt.Errorf("config file %q: invalid YAML near line %d", path, lineNo)
		}
		key, value, found := strings.Cut(trimmed, ":")
		if !found {
			return nil, fmt.Errorf("config file %q: invalid YAML near line %d", path, lineNo)
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		currentList = ""
		switch key {
		case "interface":
			if value == "" {
				return nil, fmt.Errorf("config file %q: live.interface must not be empty", path)
			}
			config.Interface = value
		case "exclude_src_ips", "exclude_dst_ips":
			if value != "" {
				return nil, fmt.Errorf("config file %q: %s must use YAML list syntax", path, key)
			}
			currentList = key
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("reading config file %q: %w", path, err)
	}
	if config.Interface == "" {
		return nil, fmt.Errorf("config file %q: missing live.interface", path)
	}
	if err := validateConfiguredIPs(path, "exclude_src_ips", config.ExcludeSrcIPs); err != nil {
		return nil, err
	}
	if err := validateConfiguredIPs(path, "exclude_dst_ips", config.ExcludeDstIPs); err != nil {
		return nil, err
	}
	return config, nil
}

func validateConfiguredIPs(path, field string, values []string) error {
	for _, value := range values {
		if net.ParseIP(value) == nil {
			return fmt.Errorf("config file %q: %s contains invalid IP %q", path, field, value)
		}
	}
	return nil
}
