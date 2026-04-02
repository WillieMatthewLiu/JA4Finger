package engine

import (
	"context"
	"errors"
	"testing"

	"github.com/nextinfra/ja4finger/capture"
)

func TestNewPipelineRequiresSource(t *testing.T) {
	handler := PacketHandlerFunc(func(context.Context, capture.PacketEvent) error { return nil })
	if _, err := NewPipeline(context.Background(), nil, handler); err == nil {
		t.Fatalf("expected error when source is nil")
	}
}

func TestNewPipelineRequiresProcessor(t *testing.T) {
	src := newStubSource()
	if _, err := NewPipeline(context.Background(), src, nil); err == nil {
		t.Fatalf("expected error when processor is nil")
	}
}

func TestPipelineProcessesEventsAndErrors(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	src := newStubSource()
	handlerErr := errors.New("handler failure")
	sourceErr := errors.New("source failure")
	handler := PacketHandlerFunc(func(context.Context, capture.PacketEvent) error {
		return handlerErr
	})

	pipeline, err := NewPipeline(ctx, src, handler)
	if err != nil {
		t.Fatalf("creating pipeline: %v", err)
	}
	defer pipeline.Close()

	src.events <- capture.PacketEvent{Source: "stub"}
	close(src.events)
	src.errors <- sourceErr
	close(src.errors)

	pipeline.Wait()

	var sawHandlerErr, sawSourceErr bool
	for err := range pipeline.Errors() {
		if errors.Is(err, handlerErr) {
			sawHandlerErr = true
		}
		if errors.Is(err, sourceErr) {
			sawSourceErr = true
		}
	}

	if !sawHandlerErr {
		t.Fatal("handler error was not surfaced")
	}
	if !sawSourceErr {
		t.Fatal("source error was not surfaced")
	}
}

type stubSource struct {
	events chan capture.PacketEvent
	errors chan error
}

func newStubSource() *stubSource {
	return &stubSource{
		events: make(chan capture.PacketEvent, 1),
		errors: make(chan error, 1),
	}
}

func (s *stubSource) Events() <-chan capture.PacketEvent {
	return s.events
}

func (s *stubSource) Errors() <-chan error {
	return s.errors
}
