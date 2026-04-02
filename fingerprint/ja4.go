package fingerprint

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/nextinfra/ja4finger/decoder"
)

var ErrUnsupportedFingerprint = errors.New("fingerprint: unsupported decoded traffic")

type Result struct {
	SrcIP           string `json:"src_ip"`
	SrcPort         uint16 `json:"src_port"`
	DstIP           string `json:"dst_ip"`
	DstPort         uint16 `json:"dst_port"`
	Protocol        string `json:"protocol"`
	FingerprintType string `json:"fingerprint_type"`
	Fingerprint     string `json:"fingerprint"`
	CipherHashInput string `json:"cipher_hash_input,omitempty"`
	ExtHashInput    string `json:"ext_hash_input,omitempty"`
}

type Fingerprinter interface {
	Name() string
	Fingerprint(*decoder.ClientHello) (*Result, error)
}

type Registry struct {
	fingerprinters []Fingerprinter
}

func NewRegistry(fingerprinters ...Fingerprinter) *Registry {
	return &Registry{fingerprinters: append([]Fingerprinter(nil), fingerprinters...)}
}

func (r *Registry) Fingerprint(hello *decoder.ClientHello) (*Result, error) {
	for _, fingerprinter := range r.fingerprinters {
		result, err := fingerprinter.Fingerprint(hello)
		if errors.Is(err, ErrUnsupportedFingerprint) {
			continue
		}
		return result, err
	}
	return nil, ErrUnsupportedFingerprint
}

type JA4Fingerprinter struct{}

func (JA4Fingerprinter) Name() string {
	return "ja4"
}

func (JA4Fingerprinter) Fingerprint(hello *decoder.ClientHello) (*Result, error) {
	if hello == nil {
		return nil, ErrUnsupportedFingerprint
	}

	ciphers := filterGREASE(hello.CipherSuites)
	extensions := filterGREASE(hello.Extensions)
	sigAlgs := filterGREASE(hello.SignatureAlgorithms)

	parts := []string{
		"t",
		versionCode(selectVersion(hello)),
		sniCode(hello.ServerName),
		countCode(len(ciphers)),
		countCode(len(extensions)),
		alpnCode(hello.ALPNProtocols),
	}

	cipherInputs := formatHexList(ciphers)
	cipherInput := strings.Join(cipherInputs, ",")

	extInput := buildExtHashInput(extensions, sigAlgs)

	fingerprint := strings.Join(parts, "") + "_" + hashString(cipherInput) + "_" + hashString(extInput)
	return &Result{
		SrcIP:           hello.SrcIP,
		SrcPort:         hello.SrcPort,
		DstIP:           hello.DstIP,
		DstPort:         hello.DstPort,
		Protocol:        hello.Protocol,
		FingerprintType: "ja4",
		Fingerprint:     fingerprint,
		CipherHashInput: cipherInput,
		ExtHashInput:    extInput,
	}, nil
}

func selectVersion(hello *decoder.ClientHello) uint16 {
	best := hello.LegacyVersion
	for _, version := range hello.SupportedVersions {
		if isGREASE(version) {
			continue
		}
		if version > best {
			best = version
		}
	}
	return best
}

func versionCode(version uint16) string {
	switch version {
	case 0x0301:
		return "10"
	case 0x0302:
		return "11"
	case 0x0303:
		return "12"
	case 0x0304:
		return "13"
	default:
		return "00"
	}
}

func sniCode(name string) string {
	if decoder.IsDomainName(name) {
		return "d"
	}
	return "i"
}

func countCode(count int) string {
	if count > 99 {
		count = 99
	}
	return fmt.Sprintf("%02d", count)
}

func alpnCode(protocols []string) string {
	if len(protocols) == 0 {
		return "00"
	}
	alpn := protocols[0]
	if alpn == "" {
		return "00"
	}
	if alpn[0] > 127 {
		return "99"
	}
	if len(alpn) <= 2 {
		return alpn
	}
	return string([]byte{alpn[0], alpn[len(alpn)-1]})
}

func filterGREASE(values []uint16) []uint16 {
	filtered := make([]uint16, 0, len(values))
	for _, value := range values {
		if isGREASE(value) {
			continue
		}
		filtered = append(filtered, value)
	}
	return filtered
}

func formatHexList(values []uint16) []string {
	formatted := make([]string, 0, len(values))
	for _, value := range values {
		formatted = append(formatted, decoder.FormatUint16Hex(value))
	}
	sort.Strings(formatted)
	return formatted
}

func buildExtHashInput(extensions, sigAlgs []uint16) string {
	filteredExts := make([]uint16, 0, len(extensions))
	for _, ext := range extensions {
		if ext == 0x0000 || ext == 0x0010 {
			continue
		}
		filteredExts = append(filteredExts, ext)
	}

	extPart := strings.Join(formatHexList(filteredExts), ",")
	if len(sigAlgs) == 0 {
		return extPart
	}

	return extPart + "_" + strings.Join(formatHexListPreserveOrder(sigAlgs), ",")
}

func formatHexListPreserveOrder(values []uint16) []string {
	formatted := make([]string, 0, len(values))
	for _, value := range values {
		formatted = append(formatted, decoder.FormatUint16Hex(value))
	}
	return formatted
}

func hashString(value string) string {
	if value == "" {
		return "000000000000"
	}
	sum := sha256.Sum256([]byte(value))
	return fmt.Sprintf("%x", sum[:])[:12]
}

func isGREASE(value uint16) bool {
	hi := byte(value >> 8)
	lo := byte(value)
	return hi == lo && hi&0x0f == 0x0a
}
