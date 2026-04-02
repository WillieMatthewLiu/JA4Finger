package engine

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/nextinfra/ja4finger/capture"
	"github.com/nextinfra/ja4finger/decoder"
	"github.com/nextinfra/ja4finger/fingerprint"
	"github.com/nextinfra/ja4finger/output"
)

type ResultEmitter interface {
	Emit(*fingerprint.Result) error
}

type FingerprintProcessor struct {
	registry        *fingerprint.Registry
	emitter         ResultEmitter
	debugHashInputs bool
}

func NewFingerprintProcessor(emitter ResultEmitter, debugHashInputs bool) *FingerprintProcessor {
	return &FingerprintProcessor{
		registry:        fingerprint.NewRegistry(fingerprint.JA4Fingerprinter{}),
		emitter:         emitter,
		debugHashInputs: debugHashInputs,
	}
}

func (p *FingerprintProcessor) ProcessPacket(_ context.Context, evt capture.PacketEvent) error {
	hello, err := decoder.DecodeTLSClientHello(evt)
	if err != nil {
		if errors.Is(err, decoder.ErrNotCandidate) {
			return nil
		}
		return err
	}

	result, err := p.registry.Fingerprint(hello)
	if err != nil {
		if errors.Is(err, fingerprint.ErrUnsupportedFingerprint) {
			return nil
		}
		return err
	}
	if !p.debugHashInputs {
		result.CipherHashInput = ""
		result.ExtHashInput = ""
	}

	return p.emitter.Emit(result)
}

func RunPCAP(ctx context.Context, path string, stdout, stderr io.Writer, debugHashInputs bool, logFile string) error {
	source, err := capture.NewPCAPSource(ctx, path)
	if err != nil {
		return err
	}
	return runSource(ctx, source, stdout, stderr, debugHashInputs, logFile)
}

func RunLive(ctx context.Context, iface string, stdout, stderr io.Writer, debugHashInputs bool, logFile string) error {
	source, err := capture.NewLiveSource(ctx, iface)
	if err != nil {
		return err
	}
	return runSource(ctx, source, stdout, stderr, debugHashInputs, logFile)
}

func runSource(ctx context.Context, source *capture.Source, stdout, stderr io.Writer, debugHashInputs bool, logFile string) error {
	defer source.Close()

	resultWriter, resultCloser, err := buildResultWriter(stdout, logFile)
	if err != nil {
		return err
	}
	if resultCloser != nil {
		defer resultCloser.Close()
	}

	processor := NewFingerprintProcessor(output.NewJSONLEmitter(resultWriter), debugHashInputs)
	pipeline, err := NewPipeline(ctx, source, processor)
	if err != nil {
		return err
	}
	defer pipeline.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		for runErr := range pipeline.Errors() {
			if stderr == nil {
				continue
			}
			fmt.Fprintln(stderr, runErr)
		}
	}()

	go func() {
		if ctx == nil {
			return
		}
		<-ctx.Done()
		_ = source.Close()
	}()

	pipeline.Wait()
	<-done
	return nil
}

func buildResultWriter(stdout io.Writer, logFile string) (io.Writer, io.Closer, error) {
	writers := make([]io.Writer, 0, 2)
	if stdout != nil {
		writers = append(writers, stdout)
	}

	if strings.TrimSpace(logFile) == "" {
		if len(writers) == 0 {
			return io.Discard, nil, nil
		}
		return combineResultWriters(writers), nil, nil
	}

	logDir := filepath.Dir(logFile)
	if err := os.MkdirAll(logDir, 0o755); err != nil {
		return nil, nil, fmt.Errorf("creating log directory: %w", err)
	}
	file, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return nil, nil, fmt.Errorf("opening log file: %w", err)
	}
	writers = append(writers, file)
	return combineResultWriters(writers), file, nil
}

func combineResultWriters(writers []io.Writer) io.Writer {
	switch len(writers) {
	case 0:
		return io.Discard
	case 1:
		return writers[0]
	default:
		return io.MultiWriter(writers...)
	}
}
