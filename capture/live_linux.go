//go:build linux

package capture

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/afpacket"
	"github.com/google/gopacket/layers"
)

const (
	afpacketFrameSize = 1 << 16
	afpacketBlockSize = 1 << 20
	afpacketNumBlocks = 8
)

type afpacketReader struct {
	handle *afpacket.TPacket
}

func newAfpacketReader(iface string) (*afpacketReader, error) {
	handle, err := afpacket.NewTPacket(
		afpacket.OptInterface(iface),
		afpacket.OptFrameSize(afpacketFrameSize),
		afpacket.OptBlockSize(afpacketBlockSize),
		afpacket.OptNumBlocks(afpacketNumBlocks),
		afpacket.OptPollTimeout(time.Second),
		afpacket.SocketRaw,
		afpacket.TPacketVersion3,
	)
	if err != nil {
		return nil, err
	}
	return &afpacketReader{handle: handle}, nil
}

func (r *afpacketReader) ReadPacketData() ([]byte, gopacket.CaptureInfo, error) {
	return r.handle.ReadPacketData()
}

func (r *afpacketReader) LinkType() layers.LinkType {
	return layers.LinkTypeEthernet
}

func (r *afpacketReader) Close() error {
	r.handle.Close()
	return nil
}

func (r *afpacketReader) RetryOnError(err error) bool {
	return errors.Is(err, afpacket.ErrTimeout)
}

// NewLiveSource opens iface and streams packets using afpacket (Linux-only).
func NewLiveSource(ctx context.Context, iface string) (*Source, error) {
	iface = strings.TrimSpace(iface)
	if iface == "" {
		return nil, errors.New("capture: interface name is required")
	}
	info, err := net.InterfaceByName(iface)
	if err != nil {
		return nil, fmt.Errorf("live interface %q: %w", iface, err)
	}
	if info.Flags&net.FlagLoopback != 0 {
		return nil, fmt.Errorf("live interface %q: loopback interfaces are not supported", iface)
	}
	if len(info.HardwareAddr) == 0 {
		return nil, fmt.Errorf("live interface %q: unsupported link type", iface)
	}
	reader, err := newAfpacketReader(iface)
	if err != nil {
		return nil, fmt.Errorf("opening live interface %q: %w", iface, err)
	}
	return newSource(ctx, reader, iface), nil
}
