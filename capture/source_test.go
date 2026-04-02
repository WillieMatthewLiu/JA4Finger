package capture

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

var errRetryable = errors.New("retryable read timeout")

func TestNewLiveSourceInvalidInterface(t *testing.T) {
	_, err := NewLiveSource(context.Background(), "nonexistent0")
	if err == nil {
		t.Fatalf("expected error creating live source for invalid interface")
	}
	message := err.Error()
	if strings.Contains(message, "requires Linux/AF_PACKET support") {
		return
	}
	if !strings.Contains(message, "network interface") {
		t.Fatalf("expected network interface error, got %v", err)
	}
}

func TestSourceIgnoresRetryableErrors(t *testing.T) {
	reader := &retryableReader{}
	src := newSource(context.Background(), reader, "retry")
	defer src.Close()

	select {
	case evt, ok := <-src.Events():
		if !ok {
			t.Fatalf("events channel closed unexpectedly")
		}
		if len(evt.Packet.Data()) == 0 {
			t.Fatalf("expected payload from retryable reader")
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timeout waiting for event")
	}

	select {
	case err := <-src.Errors():
		if err != nil {
			t.Fatalf("unexpected error from retryable reader: %v", err)
		}
	default:
	}
}

func TestSourceCloseUnblocksReader(t *testing.T) {
	reader := newBlockingReader()
	src := newSource(context.Background(), reader, "block")

	done := make(chan struct{})
	errCh := make(chan error, 1)
	go func() {
		defer close(done)
		errCh <- src.Close()
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatalf("timeout waiting for Close to return")
	}
	if err := <-errCh; err != nil {
		t.Fatalf("closing source: %v", err)
	}
}

func TestNewPCAPSourceUnreadableFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing.pcap")
	_, err := NewPCAPSource(context.Background(), path)
	if err == nil {
		t.Fatalf("expected error opening missing PCAP file")
	}
}

func TestPCAPSourceStreamsPacket(t *testing.T) {
	path := writeTestPCAP(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	src, err := NewPCAPSource(ctx, path)
	if err != nil {
		t.Fatalf("unexpected error creating PCAP source: %v", err)
	}
	defer func() {
		if closeErr := src.Close(); closeErr != nil {
			t.Fatalf("closing source: %v", closeErr)
		}
	}()

	select {
	case evt, ok := <-src.Events():
		if !ok {
			t.Fatalf("events channel closed unexpectedly")
		}
		if evt.Packet == nil {
			t.Fatalf("expected packet but got nil")
		}
		if evt.Source != path {
			t.Fatalf("unexpected source name: %s", evt.Source)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timeout waiting for packet event")
	}

	select {
	case err := <-src.Errors():
		if err != nil {
			t.Fatalf("unexpected runtime error: %v", err)
		}
	default:
	}
}

func writeTestPCAP(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "test.pcap")
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("creating PCAP file: %v", err)
	}
	defer f.Close()
	writer := pcapgo.NewWriter(f)
	if err := writer.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
		t.Fatalf("writing file header: %v", err)
	}

	packet := buildTestPacket(t)
	if err := writer.WritePacket(gopacket.CaptureInfo{
		Timestamp:     time.Now(),
		CaptureLength: len(packet),
		Length:        len(packet),
	}, packet); err != nil {
		t.Fatalf("writing packet: %v", err)
	}
	return path
}

func buildTestPacket(t *testing.T) []byte {
	t.Helper()
	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01},
		DstMAC:       net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x02},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{
		Version:  4,
		TTL:      64,
		SrcIP:    net.IPv4(192, 168, 0, 1),
		DstIP:    net.IPv4(192, 168, 0, 2),
		Protocol: layers.IPProtocolTCP,
	}
	tcp := &layers.TCP{
		SrcPort: layers.TCPPort(12345),
		DstPort: layers.TCPPort(80),
		SYN:     true,
		Window:  14600,
	}
	if err := tcp.SetNetworkLayerForChecksum(ip); err != nil {
		t.Fatalf("setting checksum: %v", err)
	}
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	if err := gopacket.SerializeLayers(buf, opts, eth, ip, tcp); err != nil {
		t.Fatalf("serializing packet: %v", err)
	}
	return buf.Bytes()
}

type retryableReader struct {
	stage int
}

func (r *retryableReader) ReadPacketData() ([]byte, gopacket.CaptureInfo, error) {
	switch r.stage {
	case 0:
		r.stage++
		return nil, gopacket.CaptureInfo{}, errRetryable
	case 1:
		r.stage++
		return []byte{0x01}, gopacket.CaptureInfo{
			Timestamp:     time.Now(),
			CaptureLength: 1,
			Length:        1,
		}, nil
	default:
		return nil, gopacket.CaptureInfo{}, io.EOF
	}
}

func (r *retryableReader) LinkType() layers.LinkType {
	return layers.LinkTypeEthernet
}

func (r *retryableReader) Close() error {
	return nil
}

func (r *retryableReader) RetryOnError(err error) bool {
	return errors.Is(err, errRetryable)
}

type blockingReader struct {
	release chan struct{}
}

func newBlockingReader() *blockingReader {
	return &blockingReader{release: make(chan struct{})}
}

func (b *blockingReader) ReadPacketData() ([]byte, gopacket.CaptureInfo, error) {
	<-b.release
	return nil, gopacket.CaptureInfo{}, io.EOF
}

func (b *blockingReader) LinkType() layers.LinkType {
	return layers.LinkTypeEthernet
}

func (b *blockingReader) Close() error {
	close(b.release)
	return nil
}

func (b *blockingReader) RetryOnError(error) bool {
	return false
}
