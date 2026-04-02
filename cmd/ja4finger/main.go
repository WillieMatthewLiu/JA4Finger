package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"

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
		parsed, err := parseCommandFlags("live", args[1:], "interface", "i", "name of the network interface to capture on")
		if err != nil {
			return err
		}
		return runLiveMode(ctx, parsed.value, stdout, stderr, parsed.debugHashInputs)
	case "pcap":
		parsed, err := parseCommandFlags("pcap", args[1:], "file", "f", "path to the PCAP file to analyze")
		if err != nil {
			return err
		}
		return runPCAPMode(ctx, parsed.value, stdout, stderr, parsed.debugHashInputs)
	default:
		return fmt.Errorf("unknown subcommand %q", args[0])
	}
}

type commandFlags struct {
	value           string
	debugHashInputs bool
}

func parseCommandFlags(subcommand string, args []string, longName, shortName, description string) (*commandFlags, error) {
	fs := flag.NewFlagSet(subcommand, flag.ContinueOnError)
	longVal := fs.String(longName, "", description)
	shortVal := fs.String(shortName, "", fmt.Sprintf("short alias for --%s", longName))
	debugHashInputs := fs.Bool("debug-hash-inputs", false, "include JA4 pre-hash input strings in output")
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
	return &commandFlags{
		value:           value,
		debugHashInputs: *debugHashInputs,
	}, nil
}
