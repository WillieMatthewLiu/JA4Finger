package fingerprint

import (
	"testing"

	"github.com/nextinfra/ja4finger/decoder"
)

func TestJA4FingerprinterBuildsExpectedFingerprint(t *testing.T) {
	hello := &decoder.ClientHello{
		SrcIP:               "192.168.0.10",
		SrcPort:             54321,
		DstIP:               "192.168.0.20",
		DstPort:             443,
		Protocol:            "tls",
		LegacyVersion:       0x0303,
		SupportedVersions:   []uint16{0x7a7a, 0x0304, 0x0303},
		ServerName:          "example.com",
		ALPNProtocols:       []string{"h2"},
		CipherSuites:        []uint16{0x1301, 0x1302, 0x0a0a, 0xc02f},
		Extensions:          []uint16{0x0a0a, 0x0000, 0x0010, 0x002b, 0x000d},
		SignatureAlgorithms: []uint16{0x0403, 0x0804},
	}

	result, err := (JA4Fingerprinter{}).Fingerprint(hello)
	if err != nil {
		t.Fatalf("Fingerprint returned error: %v", err)
	}

	expected := "t13d0304h2_40b44b994229_ef5f37ab036a"
	if result.Fingerprint != expected {
		t.Fatalf("unexpected fingerprint: %s", result.Fingerprint)
	}
	if result.FingerprintType != "ja4" {
		t.Fatalf("unexpected fingerprint type: %s", result.FingerprintType)
	}
	if result.DstIP != "192.168.0.20" {
		t.Fatalf("unexpected destination IP: %s", result.DstIP)
	}
	if result.DstPort != 443 {
		t.Fatalf("unexpected destination port: %d", result.DstPort)
	}
	if result.CipherHashInput != "1301,1302,c02f" {
		t.Fatalf("unexpected cipher hash input: %s", result.CipherHashInput)
	}
	if result.ExtHashInput != "000d,002b_0403,0804" {
		t.Fatalf("unexpected ext hash input: %s", result.ExtHashInput)
	}
}

func TestRegistryUsesRegisteredFingerprinter(t *testing.T) {
	registry := NewRegistry(JA4Fingerprinter{})
	result, err := registry.Fingerprint(&decoder.ClientHello{
		Protocol:            "tls",
		LegacyVersion:       0x0303,
		SupportedVersions:   []uint16{0x0304},
		ServerName:          "example.com",
		ALPNProtocols:       []string{"h2"},
		CipherSuites:        []uint16{0x1301},
		Extensions:          []uint16{0x0000, 0x0010, 0x002b},
		SignatureAlgorithms: []uint16{},
	})
	if err != nil {
		t.Fatalf("registry returned error: %v", err)
	}
	if result.FingerprintType != "ja4" {
		t.Fatalf("unexpected fingerprint type: %s", result.FingerprintType)
	}
}
