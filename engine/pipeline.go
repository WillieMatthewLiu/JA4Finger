package engine

import (
	"context"
	"errors"
	"sync"

	"github.com/nextinfra/ja4finger/capture"
)

const defaultPipelineErrorBuffer = 64

// PacketProcessor processes PacketEvents delivered by a capture source.
type PacketProcessor interface {
	ProcessPacket(context.Context, capture.PacketEvent) error
}

// PacketHandlerFunc allows functions to satisfy PacketProcessor.
type PacketHandlerFunc func(context.Context, capture.PacketEvent) error

// ProcessPacket calls the wrapped function if it is not nil.
func (fn PacketHandlerFunc) ProcessPacket(ctx context.Context, evt capture.PacketEvent) error {
	if fn == nil {
		return nil
	}
	return fn(ctx, evt)
}

// Pipeline wires a capture source into a packet processor and exposes runtime errors.
type Pipeline struct {
	source    capture.EventSource
	processor PacketProcessor
	errors    chan error
	ctx       context.Context
	cancel    context.CancelFunc
	wg        sync.WaitGroup
	errorFeed chan error
	forwardWg sync.WaitGroup
}

// NewPipeline validates arguments, starts the processing loop, and returns the pipeline.
func NewPipeline(ctx context.Context, source capture.EventSource, processor PacketProcessor) (*Pipeline, error) {
	if source == nil {
		return nil, errors.New("engine: capture source is required")
	}
	if processor == nil {
		return nil, errors.New("engine: packet processor is required")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithCancel(ctx)
	p := &Pipeline{
		source:    source,
		processor: processor,
		errors:    make(chan error, defaultPipelineErrorBuffer),
		errorFeed: make(chan error, defaultPipelineErrorBuffer),
		ctx:       ctx,
		cancel:    cancel,
	}
	p.forwardWg.Add(1)
	go p.forwardErrors()
	p.wg.Add(1)
	go p.run()
	return p, nil
}

func (p *Pipeline) run() {
	defer func() {
		close(p.errorFeed)
		p.wg.Done()
	}()

	events := p.source.Events()
	errs := p.source.Errors()
	for {
		if events == nil && errs == nil {
			return
		}
		select {
		case <-p.ctx.Done():
			return
		case evt, ok := <-events:
			if !ok {
				events = nil
				continue
			}
			if err := p.processor.ProcessPacket(p.ctx, evt); err != nil {
				p.emitError(err)
			}
		case err, ok := <-errs:
			if !ok {
				errs = nil
				continue
			}
			p.emitError(err)
		}
	}
}

func (p *Pipeline) emitError(err error) {
	select {
	case <-p.ctx.Done():
	case p.errorFeed <- err:
	}
}

func (p *Pipeline) forwardErrors() {
	defer func() {
		close(p.errors)
		p.forwardWg.Done()
	}()
	for err := range p.errorFeed {
		select {
		case <-p.ctx.Done():
			return
		case p.errors <- err:
		}
	}
}

// Errors exposes runtime errors from the capture source and processor.
func (p *Pipeline) Errors() <-chan error {
	return p.errors
}

// Close cancels the pipeline and waits for the processing loop to exit.
func (p *Pipeline) Close() {
	p.cancel()
	p.wg.Wait()
	p.forwardWg.Wait()
}

// Wait blocks until the pipeline processing loop exits.
func (p *Pipeline) Wait() {
	p.wg.Wait()
}
