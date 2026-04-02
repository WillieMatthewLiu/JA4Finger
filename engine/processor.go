package engine

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/nextinfra/ja4finger/capture"
	"github.com/nextinfra/ja4finger/decoder"
	"github.com/nextinfra/ja4finger/fingerprint"
	"github.com/nextinfra/ja4finger/output"
)

type ResultEmitter interface {
	Emit(*fingerprint.Result) error
}

type FingerprintProcessor struct {
	registry *fingerprint.Registry
	emitter  ResultEmitter
}

func NewFingerprintProcessor(emitter ResultEmitter) *FingerprintProcessor {
	return &FingerprintProcessor{
		registry: fingerprint.NewRegistry(fingerprint.JA4Fingerprinter{}),
		emitter:  emitter,
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

	return p.emitter.Emit(result)
}

func RunPCAP(ctx context.Context, path string, stdout, stderr io.Writer) error {
	source, err := capture.NewPCAPSource(ctx, path)
	if err != nil {
		return err
	}
	return runSource(ctx, source, stdout, stderr)
}

func RunLive(ctx context.Context, iface string, stdout, stderr io.Writer) error {
	source, err := capture.NewLiveSource(ctx, iface)
	if err != nil {
		return err
	}
	return runSource(ctx, source, stdout, stderr)
}

func runSource(ctx context.Context, source *capture.Source, stdout, stderr io.Writer) error {
	defer source.Close()

	processor := NewFingerprintProcessor(output.NewJSONLEmitter(stdout))
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
