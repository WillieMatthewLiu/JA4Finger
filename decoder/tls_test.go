package decoder

import (
	"errors"
	"net"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/nextinfra/ja4finger/capture"
)

func TestDecodeTLSClientHelloParsesExpectedFields(t *testing.T) {
	evt := testTLSEvent(t, testClientHelloRecord())

	hello, err := DecodeTLSClientHello(evt)
	if err != nil {
		t.Fatalf("DecodeTLSClientHello returned error: %v", err)
	}

	if hello.SrcIP != "192.168.0.10" {
		t.Fatalf("unexpected source IP: %s", hello.SrcIP)
	}
	if hello.SrcPort != 54321 {
		t.Fatalf("unexpected source port: %d", hello.SrcPort)
	}
	if hello.DstIP != "192.168.0.20" {
		t.Fatalf("unexpected destination IP: %s", hello.DstIP)
	}
	if hello.DstPort != 443 {
		t.Fatalf("unexpected destination port: %d", hello.DstPort)
	}
	if hello.Protocol != "tls" {
		t.Fatalf("unexpected protocol: %s", hello.Protocol)
	}
	if hello.ServerName != "example.com" {
		t.Fatalf("unexpected server name: %s", hello.ServerName)
	}
	if len(hello.ALPNProtocols) != 1 || hello.ALPNProtocols[0] != "h2" {
		t.Fatalf("unexpected ALPN protocols: %#v", hello.ALPNProtocols)
	}
	if len(hello.CipherSuites) != 4 {
		t.Fatalf("unexpected cipher suite count: %d", len(hello.CipherSuites))
	}
	if len(hello.Extensions) != 5 {
		t.Fatalf("unexpected extension count: %d", len(hello.Extensions))
	}
	if len(hello.SupportedVersions) != 3 {
		t.Fatalf("unexpected supported versions: %#v", hello.SupportedVersions)
	}
	if len(hello.SignatureAlgorithms) != 2 {
		t.Fatalf("unexpected signature algorithms: %#v", hello.SignatureAlgorithms)
	}
}

func TestDecodeTLSClientHelloRejectsNonTLS(t *testing.T) {
	evt := testTLSEvent(t, []byte("not tls"))

	_, err := DecodeTLSClientHello(evt)
	if !errors.Is(err, ErrNotCandidate) {
		t.Fatalf("expected ErrNotCandidate, got %v", err)
	}
}

func TestDecodeTLSClientHelloRequiresCompleteRecord(t *testing.T) {
	record := testClientHelloRecord()
	evt := testTLSEvent(t, record[:len(record)-1])

	_, err := DecodeTLSClientHello(evt)
	if !errors.Is(err, ErrNeedMoreData) {
		t.Fatalf("expected ErrNeedMoreData, got %v", err)
	}
}

func testTLSEvent(t *testing.T, payload []byte) capture.PacketEvent {
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

func testClientHelloRecord() []byte {
	extensions := []byte{
		0x0a, 0x0a, 0x00, 0x00, // GREASE extension
		0x00, 0x00, 0x00, 0x10, 0x00, 0x0e, 0x00, 0x00, 0x0b, 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm',
		0x00, 0x10, 0x00, 0x05, 0x00, 0x03, 0x02, 'h', '2',
		0x00, 0x2b, 0x00, 0x07, 0x06, 0x7a, 0x7a, 0x03, 0x04, 0x03, 0x03,
		0x00, 0x0d, 0x00, 0x06, 0x00, 0x04, 0x04, 0x03, 0x08, 0x04,
	}

	body := []byte{
		0x03, 0x03, // legacy version
	}
	body = append(body, make([]byte, 32)...) // random
	body = append(body, 0x00)                // session id len
	body = append(body, 0x00, 0x08,          // cipher suites len
		0x13, 0x01,
		0x13, 0x02,
		0x0a, 0x0a,
		0xc0, 0x2f,
	)
	body = append(body, 0x01, 0x00) // compression methods
	body = append(body, byte(len(extensions)>>8), byte(len(extensions)))
	body = append(body, extensions...)

	record := []byte{
		0x16, 0x03, 0x01,
	}
	recordLen := 4 + len(body)
	record = append(record, byte(recordLen>>8), byte(recordLen))
	record = append(record, 0x01, byte(len(body)>>16), byte(len(body)>>8), byte(len(body)))
	record = append(record, body...)
	return record
}
