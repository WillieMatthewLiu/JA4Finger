package decoder

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"

	"github.com/google/gopacket/layers"
	"github.com/nextinfra/ja4finger/capture"
)

var (
	ErrNotCandidate = errors.New("decoder: packet is not a supported TLS client candidate")
	ErrNeedMoreData = errors.New("decoder: incomplete TLS client hello")
)

const (
	tlsRecordTypeHandshake      = 0x16
	tlsHandshakeTypeClientHello = 0x01
	extServerName               = 0x0000
	extSignatureAlgorithms      = 0x000d
	extALPN                     = 0x0010
	extSupportedVersions        = 0x002b
)

type ClientHello struct {
	SrcIP               string
	SrcPort             uint16
	Protocol            string
	LegacyVersion       uint16
	SupportedVersions   []uint16
	ServerName          string
	ALPNProtocols       []string
	CipherSuites        []uint16
	Extensions          []uint16
	SignatureAlgorithms []uint16
}

func DecodeTLSClientHello(evt capture.PacketEvent) (*ClientHello, error) {
	srcIP, srcPort, payload, err := extractNetworkData(evt)
	if err != nil {
		return nil, err
	}

	hello, err := parseTLSClientHello(payload)
	if err != nil {
		return nil, err
	}
	hello.SrcIP = srcIP
	hello.SrcPort = srcPort
	hello.Protocol = "tls"
	return hello, nil
}

func extractNetworkData(evt capture.PacketEvent) (string, uint16, []byte, error) {
	packet := evt.Packet
	if packet == nil {
		return "", 0, nil, ErrNotCandidate
	}

	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		return "", 0, nil, ErrNotCandidate
	}
	tcp, ok := tcpLayer.(*layers.TCP)
	if !ok || len(tcp.Payload) == 0 {
		return "", 0, nil, ErrNotCandidate
	}

	switch {
	case packet.Layer(layers.LayerTypeIPv4) != nil:
		ip := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
		return ip.SrcIP.String(), uint16(tcp.SrcPort), tcp.Payload, nil
	case packet.Layer(layers.LayerTypeIPv6) != nil:
		ip := packet.Layer(layers.LayerTypeIPv6).(*layers.IPv6)
		return ip.SrcIP.String(), uint16(tcp.SrcPort), tcp.Payload, nil
	default:
		return "", 0, nil, ErrNotCandidate
	}
}

func parseTLSClientHello(data []byte) (*ClientHello, error) {
	if len(data) < 5 {
		return nil, ErrNeedMoreData
	}
	if data[0] != tlsRecordTypeHandshake {
		return nil, ErrNotCandidate
	}

	recordLen := int(binary.BigEndian.Uint16(data[3:5]))
	if len(data) < 5+recordLen {
		return nil, ErrNeedMoreData
	}
	record := data[5 : 5+recordLen]
	if len(record) < 4 {
		return nil, ErrNeedMoreData
	}
	if record[0] != tlsHandshakeTypeClientHello {
		return nil, ErrNotCandidate
	}

	handshakeLen := int(record[1])<<16 | int(record[2])<<8 | int(record[3])
	if len(record) < 4+handshakeLen {
		return nil, ErrNeedMoreData
	}

	body := record[4 : 4+handshakeLen]
	return parseClientHelloBody(body)
}

func parseClientHelloBody(body []byte) (*ClientHello, error) {
	if len(body) < 34 {
		return nil, ErrNeedMoreData
	}
	offset := 0
	hello := &ClientHello{
		LegacyVersion: binary.BigEndian.Uint16(body[offset : offset+2]),
	}
	offset += 2
	offset += 32 // random

	sessionIDLen := int(body[offset])
	offset++
	if len(body) < offset+sessionIDLen {
		return nil, ErrNeedMoreData
	}
	offset += sessionIDLen

	if len(body) < offset+2 {
		return nil, ErrNeedMoreData
	}
	cipherLen := int(binary.BigEndian.Uint16(body[offset : offset+2]))
	offset += 2
	if cipherLen%2 != 0 || len(body) < offset+cipherLen {
		return nil, ErrNeedMoreData
	}
	for i := 0; i < cipherLen; i += 2 {
		hello.CipherSuites = append(hello.CipherSuites, binary.BigEndian.Uint16(body[offset+i:offset+i+2]))
	}
	offset += cipherLen

	if len(body) < offset+1 {
		return nil, ErrNeedMoreData
	}
	compressionLen := int(body[offset])
	offset++
	if len(body) < offset+compressionLen {
		return nil, ErrNeedMoreData
	}
	offset += compressionLen

	if len(body) == offset {
		return hello, nil
	}
	if len(body) < offset+2 {
		return nil, ErrNeedMoreData
	}
	extensionsLen := int(binary.BigEndian.Uint16(body[offset : offset+2]))
	offset += 2
	if len(body) < offset+extensionsLen {
		return nil, ErrNeedMoreData
	}
	extensions := body[offset : offset+extensionsLen]

	for len(extensions) > 0 {
		if len(extensions) < 4 {
			return nil, ErrNeedMoreData
		}
		extType := binary.BigEndian.Uint16(extensions[:2])
		extLen := int(binary.BigEndian.Uint16(extensions[2:4]))
		extensions = extensions[4:]
		if len(extensions) < extLen {
			return nil, ErrNeedMoreData
		}
		extData := extensions[:extLen]
		extensions = extensions[extLen:]

		hello.Extensions = append(hello.Extensions, extType)

		switch extType {
		case extServerName:
			name, err := parseServerName(extData)
			if err != nil {
				return nil, err
			}
			hello.ServerName = name
		case extALPN:
			protos, err := parseALPN(extData)
			if err != nil {
				return nil, err
			}
			hello.ALPNProtocols = protos
		case extSupportedVersions:
			versions, err := parseSupportedVersions(extData)
			if err != nil {
				return nil, err
			}
			hello.SupportedVersions = versions
		case extSignatureAlgorithms:
			algs, err := parseUint16Vector(extData)
			if err != nil {
				return nil, err
			}
			hello.SignatureAlgorithms = algs
		}
	}

	return hello, nil
}

func parseServerName(data []byte) (string, error) {
	if len(data) < 2 {
		return "", ErrNeedMoreData
	}
	listLen := int(binary.BigEndian.Uint16(data[:2]))
	data = data[2:]
	if len(data) < listLen {
		return "", ErrNeedMoreData
	}
	for len(data) > 0 {
		if len(data) < 3 {
			return "", ErrNeedMoreData
		}
		nameType := data[0]
		nameLen := int(binary.BigEndian.Uint16(data[1:3]))
		data = data[3:]
		if len(data) < nameLen {
			return "", ErrNeedMoreData
		}
		name := string(data[:nameLen])
		data = data[nameLen:]
		if nameType == 0 {
			return name, nil
		}
	}
	return "", nil
}

func parseALPN(data []byte) ([]string, error) {
	if len(data) < 2 {
		return nil, ErrNeedMoreData
	}
	listLen := int(binary.BigEndian.Uint16(data[:2]))
	data = data[2:]
	if len(data) < listLen {
		return nil, ErrNeedMoreData
	}

	var protocols []string
	for len(data) > 0 {
		protoLen := int(data[0])
		data = data[1:]
		if len(data) < protoLen {
			return nil, ErrNeedMoreData
		}
		protocols = append(protocols, string(data[:protoLen]))
		data = data[protoLen:]
	}
	return protocols, nil
}

func parseSupportedVersions(data []byte) ([]uint16, error) {
	if len(data) < 1 {
		return nil, ErrNeedMoreData
	}
	listLen := int(data[0])
	data = data[1:]
	if len(data) < listLen || listLen%2 != 0 {
		return nil, ErrNeedMoreData
	}

	var versions []uint16
	for i := 0; i < listLen; i += 2 {
		versions = append(versions, binary.BigEndian.Uint16(data[i:i+2]))
	}
	return versions, nil
}

func parseUint16Vector(data []byte) ([]uint16, error) {
	if len(data) < 2 {
		return nil, ErrNeedMoreData
	}
	listLen := int(binary.BigEndian.Uint16(data[:2]))
	data = data[2:]
	if len(data) < listLen || listLen%2 != 0 {
		return nil, ErrNeedMoreData
	}
	values := make([]uint16, 0, listLen/2)
	for i := 0; i < listLen; i += 2 {
		values = append(values, binary.BigEndian.Uint16(data[i:i+2]))
	}
	return values, nil
}

func IsDomainName(host string) bool {
	return host != "" && net.ParseIP(host) == nil
}

func FormatUint16Hex(value uint16) string {
	return fmt.Sprintf("%04x", value)
}
