package engine

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/nextinfra/ja4finger/capture"
	"github.com/nextinfra/ja4finger/decoder"
	"github.com/nextinfra/ja4finger/fingerprint"
)

func TestFingerprintProcessorEmitsJA4Result(t *testing.T) {
	emitter := &stubEmitter{}
	processor := NewFingerprintProcessor(emitter, false)

	if err := processor.ProcessPacket(context.Background(), tlsEvent(t, tlsRecord())); err != nil {
		t.Fatalf("ProcessPacket returned error: %v", err)
	}

	if emitter.result == nil {
		t.Fatal("expected emitted result")
	}
	if emitter.result.Fingerprint != "t13d0304h2_40b44b994229_ef5f37ab036a" {
		t.Fatalf("unexpected fingerprint: %s", emitter.result.Fingerprint)
	}
	if emitter.result.CipherHashInput != "" || emitter.result.ExtHashInput != "" {
		t.Fatalf("did not expect debug hash inputs when debug mode is disabled: %#v", emitter.result)
	}
}

func TestFingerprintProcessorEmitsDebugHashInputsWhenEnabled(t *testing.T) {
	emitter := &stubEmitter{}
	processor := NewFingerprintProcessor(emitter, true)

	if err := processor.ProcessPacket(context.Background(), tlsEvent(t, tlsRecord())); err != nil {
		t.Fatalf("ProcessPacket returned error: %v", err)
	}

	if emitter.result == nil {
		t.Fatal("expected emitted result")
	}
	if emitter.result.CipherHashInput != "1301,1302,c02f" {
		t.Fatalf("unexpected cipher hash input: %s", emitter.result.CipherHashInput)
	}
	if emitter.result.ExtHashInput != "000d,002b_0403,0804" {
		t.Fatalf("unexpected ext hash input: %s", emitter.result.ExtHashInput)
	}
}

func TestFingerprintProcessorIgnoresUnsupportedTraffic(t *testing.T) {
	emitter := &stubEmitter{}
	processor := NewFingerprintProcessor(emitter, false)

	err := processor.ProcessPacket(context.Background(), tlsEvent(t, []byte("plain text")))
	if err != nil {
		t.Fatalf("expected unsupported traffic to be ignored, got %v", err)
	}
	if emitter.result != nil {
		t.Fatalf("did not expect emitted result: %#v", emitter.result)
	}
}

func TestFingerprintProcessorReturnsDecodeErrors(t *testing.T) {
	emitter := &stubEmitter{}
	processor := NewFingerprintProcessor(emitter, false)

	err := processor.ProcessPacket(context.Background(), tlsEvent(t, tlsRecord()[:len(tlsRecord())-1]))
	if !errors.Is(err, decoder.ErrNeedMoreData) {
		t.Fatalf("expected ErrNeedMoreData, got %v", err)
	}
}

type stubEmitter struct {
	result *fingerprint.Result
}

func (s *stubEmitter) Emit(result *fingerprint.Result) error {
	s.result = result
	return nil
}

func tlsEvent(t *testing.T, payload []byte) capture.PacketEvent {
	t.Helper()

	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01},
		DstMAC:       net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x02},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{
		Version:  4,
		TTL:      64,
		SrcIP:    net.IPv4(192, 168, 0, 10),
		DstIP:    net.IPv4(192, 168, 0, 20),
		Protocol: layers.IPProtocolTCP,
	}
	tcp := &layers.TCP{
		SrcPort: layers.TCPPort(54321),
		DstPort: layers.TCPPort(443),
		ACK:     true,
		PSH:     true,
		Seq:     1,
	}
	if err := tcp.SetNetworkLayerForChecksum(ip); err != nil {
		t.Fatalf("SetNetworkLayerForChecksum: %v", err)
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, eth, ip, tcp, gopacket.Payload(payload)); err != nil {
		t.Fatalf("SerializeLayers: %v", err)
	}

	packet := gopacket.NewPacket(buf.Bytes(), layers.LinkTypeEthernet, gopacket.Default)
	return capture.PacketEvent{Packet: packet, Source: "test", CaptureInfo: gopacket.CaptureInfo{}}
}

func tlsRecord() []byte {
	extensions := []byte{
		0x0a, 0x0a, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x10, 0x00, 0x0e, 0x00, 0x00, 0x0b, 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm',
		0x00, 0x10, 0x00, 0x05, 0x00, 0x03, 0x02, 'h', '2',
		0x00, 0x2b, 0x00, 0x07, 0x06, 0x7a, 0x7a, 0x03, 0x04, 0x03, 0x03,
		0x00, 0x0d, 0x00, 0x06, 0x00, 0x04, 0x04, 0x03, 0x08, 0x04,
	}

	body := []byte{0x03, 0x03}
	body = append(body, make([]byte, 32)...)
	body = append(body, 0x00)
	body = append(body, 0x00, 0x08, 0x13, 0x01, 0x13, 0x02, 0x0a, 0x0a, 0xc0, 0x2f)
	body = append(body, 0x01, 0x00)
	body = append(body, byte(len(extensions)>>8), byte(len(extensions)))
	body = append(body, extensions...)

	record := []byte{0x16, 0x03, 0x01}
	recordLen := 4 + len(body)
	record = append(record, byte(recordLen>>8), byte(recordLen))
	record = append(record, 0x01, byte(len(body)>>16), byte(len(body)>>8), byte(len(body)))
	record = append(record, body...)
	return record
}
