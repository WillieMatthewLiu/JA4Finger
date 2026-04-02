package capture

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

type pcapReader struct {
	file   *os.File
	reader *pcapgo.Reader
}

func newPCAPReader(path string) (*pcapReader, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	reader, err := pcapgo.NewReader(f)
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	return &pcapReader{file: f, reader: reader}, nil
}

func (r *pcapReader) ReadPacketData() ([]byte, gopacket.CaptureInfo, error) {
	return r.reader.ReadPacketData()
}

func (r *pcapReader) LinkType() layers.LinkType {
	return r.reader.LinkType()
}

func (r *pcapReader) Close() error {
	return r.file.Close()
}

func (r *pcapReader) RetryOnError(error) bool {
	return false
}

// NewPCAPSource opens path and streams packets from the PCAP file.
func NewPCAPSource(ctx context.Context, path string) (*Source, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, errors.New("capture: PCAP file path is required")
	}
	reader, err := newPCAPReader(path)
	if err != nil {
		return nil, fmt.Errorf("opening PCAP file %q: %w", path, err)
	}
	return newSource(ctx, reader, path), nil
}
