package capture

import (
	"context"
	"errors"
	"io"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

const defaultEventBuffer = 256

// PacketEvent describes a packet emitted by any capture source.
type PacketEvent struct {
	Timestamp   time.Time
	Source      string
	Packet      gopacket.Packet
	CaptureInfo gopacket.CaptureInfo
}

// EventSource abstracts a source that streams PacketEvents and surface errors.
type EventSource interface {
	Events() <-chan PacketEvent
	Errors() <-chan error
}

type packetReader interface {
	ReadPacketData() ([]byte, gopacket.CaptureInfo, error)
	LinkType() layers.LinkType
	Close() error
	RetryOnError(error) bool
}

// Source wraps a packetReader and streams packets over channels.
type Source struct {
	sourceName string
	reader     packetReader
	events     chan PacketEvent
	errors     chan error
	cancel     context.CancelFunc
	wg         sync.WaitGroup
	closeOnce  sync.Once
}

func newSource(ctx context.Context, reader packetReader, sourceName string) *Source {
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithCancel(ctx)
	s := &Source{
		sourceName: sourceName,
		reader:     reader,
		events:     make(chan PacketEvent, defaultEventBuffer),
		errors:     make(chan error, defaultEventBuffer),
		cancel:     cancel,
	}
	s.wg.Add(1)
	go s.run(ctx)
	return s
}

func (s *Source) run(ctx context.Context) {
	defer func() {
		close(s.events)
		close(s.errors)
		s.wg.Done()
	}()

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		data, ci, err := s.reader.ReadPacketData()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return
			}
			if s.reader.RetryOnError(err) {
				continue
			}
			s.emitError(err, ctx)
			return
		}

		packet := gopacket.NewPacket(data, s.reader.LinkType(), gopacket.Default)
		if metadata := packet.Metadata(); metadata != nil {
			if metadata.Timestamp.IsZero() {
				metadata.Timestamp = ci.Timestamp
			}
			metadata.CaptureInfo = ci
		}
		s.emitEvent(packet, ci, ctx)
	}
}

func (s *Source) emitEvent(packet gopacket.Packet, ci gopacket.CaptureInfo, ctx context.Context) {
	event := PacketEvent{
		Source:      s.sourceName,
		Packet:      packet,
		CaptureInfo: ci,
		Timestamp:   ci.Timestamp,
	}
	if metadata := packet.Metadata(); metadata != nil {
		if !metadata.Timestamp.IsZero() {
			event.Timestamp = metadata.Timestamp
		}
		event.CaptureInfo = metadata.CaptureInfo
	}
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now()
	}

	select {
	case <-ctx.Done():
	case s.events <- event:
	}
}

func (s *Source) emitError(err error, ctx context.Context) {
	select {
	case <-ctx.Done():
	case s.errors <- err:
	}
}

// Events returns the channel streaming PacketEvents.
func (s *Source) Events() <-chan PacketEvent {
	return s.events
}

// Errors returns the channel streaming runtime errors.
func (s *Source) Errors() <-chan error {
	return s.errors
}

// Close stops the source and releases the underlying packet reader.
func (s *Source) Close() error {
	var closeErr error
	s.closeOnce.Do(func() {
		s.cancel()
		if err := s.reader.Close(); err != nil {
			closeErr = err
		}
		s.wg.Wait()
	})
	return closeErr
}
