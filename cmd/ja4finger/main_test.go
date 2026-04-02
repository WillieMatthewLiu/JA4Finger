package main

import (
	"bytes"
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
	"github.com/nextinfra/ja4finger/engine"
)

func withStubRunners(t *testing.T, live func(context.Context, string, io.Writer, io.Writer, bool, string, engine.LiveOptions) error, pcap func(context.Context, string, io.Writer, io.Writer, bool, string) error) {
	t.Helper()

	originalLive := runLiveMode
	originalPCAP := runPCAPMode
	runLiveMode = live
	runPCAPMode = pcap
	t.Cleanup(func() {
		runLiveMode = originalLive
		runPCAPMode = originalPCAP
	})
}

func TestRunRequiresSubcommand(t *testing.T) {
	if err := run([]string{}); err == nil {
		t.Fatal("expected error when no subcommand provided")
	}
}

func TestRunLiveRequiresInterface(t *testing.T) {
	err := run([]string{"live"})
	if err == nil {
		t.Fatal("expected error when live subcommand is missing interface flag")
	}
	if !strings.Contains(err.Error(), "interface") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRunLiveAcceptsInterface(t *testing.T) {
	var called string
	withStubRunners(t,
		func(_ context.Context, iface string, _, _ io.Writer, _ bool, _ string, _ engine.LiveOptions) error {
			called = iface
			return nil
		},
		func(context.Context, string, io.Writer, io.Writer, bool, string) error { return nil },
	)
	if err := run([]string{"live", "--interface", "eth0"}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if called != "eth0" {
		t.Fatalf("unexpected interface: %s", called)
	}
}

func TestRunLiveAcceptsConfigFile(t *testing.T) {
	configPath := writeLiveConfig(t, "live:\n  interface: eth1\n")
	var called string
	withStubRunners(t,
		func(_ context.Context, iface string, _, _ io.Writer, _ bool, _ string, _ engine.LiveOptions) error {
			called = iface
			return nil
		},
		func(context.Context, string, io.Writer, io.Writer, bool, string) error { return nil },
	)

	if err := run([]string{"live", "--config", configPath}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if called != "eth1" {
		t.Fatalf("unexpected interface from config: %s", called)
	}
}

func TestRunLiveInterfaceOverridesConfigFile(t *testing.T) {
	configPath := writeLiveConfig(t, "live:\n  interface: eth1\n")
	var called string
	withStubRunners(t,
		func(_ context.Context, iface string, _, _ io.Writer, _ bool, _ string, _ engine.LiveOptions) error {
			called = iface
			return nil
		},
		func(context.Context, string, io.Writer, io.Writer, bool, string) error { return nil },
	)

	if err := run([]string{"live", "--interface", "eth0", "--config", configPath}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if called != "eth0" {
		t.Fatalf("expected CLI interface to override config, got %s", called)
	}
}

func TestRunLivePassesExcludeIPsFromConfig(t *testing.T) {
	configPath := writeLiveConfig(t, "live:\n  interface: eth1\n  exclude_src_ips:\n    - 192.168.1.10\n    - 10.0.0.5\n  exclude_dst_ips:\n    - 8.8.8.8\n")
	var got engine.LiveOptions
	withStubRunners(t,
		func(_ context.Context, _ string, _, _ io.Writer, _ bool, _ string, options engine.LiveOptions) error {
			got = options
			return nil
		},
		func(context.Context, string, io.Writer, io.Writer, bool, string) error { return nil },
	)

	if err := run([]string{"live", "--config", configPath}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got.ExcludeSrcIPs) != 2 || got.ExcludeSrcIPs[0] != "192.168.1.10" || got.ExcludeSrcIPs[1] != "10.0.0.5" {
		t.Fatalf("unexpected source exclusions: %#v", got.ExcludeSrcIPs)
	}
	if len(got.ExcludeDstIPs) != 1 || got.ExcludeDstIPs[0] != "8.8.8.8" {
		t.Fatalf("unexpected destination exclusions: %#v", got.ExcludeDstIPs)
	}
}

func TestRunLiveShortFlag(t *testing.T) {
	withStubRunners(t,
		func(context.Context, string, io.Writer, io.Writer, bool, string, engine.LiveOptions) error {
			return nil
		},
		func(context.Context, string, io.Writer, io.Writer, bool, string) error { return nil },
	)
	if err := run([]string{"live", "-i", "eth0"}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRunPCAPRequiresFile(t *testing.T) {
	err := run([]string{"pcap"})
	if err == nil {
		t.Fatal("expected error when pcap subcommand is missing file flag")
	}
	if !strings.Contains(err.Error(), "file") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRunPCAPAcceptsFile(t *testing.T) {
	var called string
	withStubRunners(t,
		func(context.Context, string, io.Writer, io.Writer, bool, string, engine.LiveOptions) error {
			return nil
		},
		func(_ context.Context, file string, _, _ io.Writer, _ bool, _ string) error {
			called = file
			return nil
		},
	)
	if err := run([]string{"pcap", "--file", "capture.pcap"}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if called != "capture.pcap" {
		t.Fatalf("unexpected file: %s", called)
	}
}

func TestRunPCAPShortFlag(t *testing.T) {
	withStubRunners(t,
		func(context.Context, string, io.Writer, io.Writer, bool, string, engine.LiveOptions) error {
			return nil
		},
		func(context.Context, string, io.Writer, io.Writer, bool, string) error { return nil },
	)
	if err := run([]string{"pcap", "-f", "capture.pcap"}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRunLiveRejectsExtraArgs(t *testing.T) {
	err := run([]string{"live", "--interface", "eth0", "extra"})
	if err == nil {
		t.Fatal("expected error when live subcommand receives extra positional args")
	}
	if !strings.Contains(err.Error(), "positional") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRunPCAPRejectsExtraArgs(t *testing.T) {
	err := run([]string{"pcap", "--file", "capture.pcap", "extra"})
	if err == nil {
		t.Fatal("expected error when pcap subcommand receives extra positional args")
	}
	if !strings.Contains(err.Error(), "positional") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRunLiveRejectsBlankInterface(t *testing.T) {
	err := run([]string{"live", "--interface", "   "})
	if err == nil {
		t.Fatal("expected error when live interface flag is blank")
	}
	if !strings.Contains(err.Error(), "interface") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRunLiveRejectsConfigWithoutInterface(t *testing.T) {
	configPath := writeLiveConfig(t, "live:\n  device: eth1\n")

	err := run([]string{"live", "--config", configPath})
	if err == nil {
		t.Fatal("expected error when live config is missing interface")
	}
	if !strings.Contains(err.Error(), "live.interface") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRunLiveRejectsInvalidExcludeSourceIP(t *testing.T) {
	configPath := writeLiveConfig(t, "live:\n  interface: eth1\n  exclude_src_ips:\n    - not-an-ip\n")

	err := run([]string{"live", "--config", configPath})
	if err == nil {
		t.Fatal("expected error when exclude source IP is invalid")
	}
	if !strings.Contains(err.Error(), "exclude_src_ips") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRunLiveRejectsInvalidExcludeDestinationIP(t *testing.T) {
	configPath := writeLiveConfig(t, "live:\n  interface: eth1\n  exclude_dst_ips:\n    - bad-ip\n")

	err := run([]string{"live", "--config", configPath})
	if err == nil {
		t.Fatal("expected error when exclude destination IP is invalid")
	}
	if !strings.Contains(err.Error(), "exclude_dst_ips") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRunLiveRejectsInvalidConfig(t *testing.T) {
	configPath := writeLiveConfig(t, "interface: [\n")

	err := run([]string{"live", "--config", configPath})
	if err == nil {
		t.Fatal("expected error when live config is invalid")
	}
	if !strings.Contains(err.Error(), "config") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRunUnknownSubcommand(t *testing.T) {
	err := run([]string{"stream"})
	if err == nil {
		t.Fatal("expected error for unknown subcommand")
	}
	if !strings.Contains(err.Error(), "unknown subcommand") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRunPropagatesExecutorError(t *testing.T) {
	expected := errors.New("boom")
	withStubRunners(t,
		func(context.Context, string, io.Writer, io.Writer, bool, string, engine.LiveOptions) error {
			return expected
		},
		func(context.Context, string, io.Writer, io.Writer, bool, string) error { return nil },
	)

	err := run([]string{"live", "--interface", "eth0"})
	if !errors.Is(err, expected) {
		t.Fatalf("expected propagated error, got %v", err)
	}
}

func TestRunPCAPReturnsStartupErrorForUnreadableFile(t *testing.T) {
	err := run([]string{"pcap", "--file", filepath.Join(t.TempDir(), "missing.pcap")})
	if err == nil {
		t.Fatal("expected unreadable PCAP file to fail")
	}
	if !strings.Contains(err.Error(), "opening PCAP file") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRunLiveReturnsStartupErrorForInvalidInterface(t *testing.T) {
	err := run([]string{"live", "--interface", "nonexistent0"})
	if err == nil {
		t.Fatal("expected invalid interface to fail")
	}
	if !strings.Contains(err.Error(), "live interface") && !strings.Contains(err.Error(), "requires Linux/AF_PACKET support") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRunPCAPUsesDefaultLogFile(t *testing.T) {
	var logFile string
	withStubRunners(t,
		func(context.Context, string, io.Writer, io.Writer, bool, string, engine.LiveOptions) error {
			return nil
		},
		func(_ context.Context, _ string, _, _ io.Writer, _ bool, path string) error {
			logFile = path
			return nil
		},
	)

	if err := run([]string{"pcap", "--file", "capture.pcap"}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	expected := defaultLogFilePath("pcap", time.Now())
	if logFile != expected {
		t.Fatalf("unexpected default log file: %s", logFile)
	}
}

func TestRunPCAPAcceptsCustomLogFile(t *testing.T) {
	var logFile string
	withStubRunners(t,
		func(context.Context, string, io.Writer, io.Writer, bool, string, engine.LiveOptions) error {
			return nil
		},
		func(_ context.Context, _ string, _, _ io.Writer, _ bool, path string) error {
			logFile = path
			return nil
		},
	)

	if err := run([]string{"pcap", "--file", "capture.pcap", "--log-file", "custom.log"}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if logFile != "custom.log" {
		t.Fatalf("unexpected custom log file: %s", logFile)
	}
}

func TestRunPCAPEmitsStableJA4Record(t *testing.T) {
	withWorkingDir(t, t.TempDir())
	path := writePCAPFixture(t, fullTLSClientHello())
	var stdout, stderr bytes.Buffer

	if err := runWithContext(context.Background(), []string{"pcap", "--file", path}, &stdout, &stderr); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	out := stdout.String()
	if !strings.Contains(out, "\"dst_ip\":\"192.168.0.20\"") {
		t.Fatalf("expected destination IP in output, got %q", out)
	}
	if !strings.Contains(out, "\"dst_port\":443") {
		t.Fatalf("expected destination port in output, got %q", out)
	}
	if !strings.Contains(out, "\"fingerprint_type\":\"ja4\"") {
		t.Fatalf("expected JA4 output, got %q", out)
	}
	if !strings.Contains(out, "\"fingerprint\":\"t13d0304h2_40b44b994229_ef5f37ab036a\"") {
		t.Fatalf("unexpected fingerprint output: %q", out)
	}
	if strings.Contains(out, "\"cipher_hash_input\"") || strings.Contains(out, "\"ext_hash_input\"") {
		t.Fatalf("did not expect debug fields in default output: %q", out)
	}
	if stderr.Len() != 0 {
		t.Fatalf("did not expect stderr output: %q", stderr.String())
	}

	logPath := defaultLogFilePath("pcap", time.Now())
	logData, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("ReadFile(%q): %v", logPath, err)
	}
	if string(logData) != out {
		t.Fatalf("expected default log file to match stdout, got %q", string(logData))
	}
}

func TestRunPCAPDebugHashInputsEmitsHashInputs(t *testing.T) {
	withWorkingDir(t, t.TempDir())
	path := writePCAPFixture(t, fullTLSClientHello())
	var stdout, stderr bytes.Buffer

	if err := runWithContext(context.Background(), []string{"pcap", "--debug-hash-inputs", "--file", path}, &stdout, &stderr); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	out := stdout.String()
	if !strings.Contains(out, "\"dst_ip\":\"192.168.0.20\"") {
		t.Fatalf("expected destination IP in debug output, got %q", out)
	}
	if !strings.Contains(out, "\"dst_port\":443") {
		t.Fatalf("expected destination port in debug output, got %q", out)
	}
	if !strings.Contains(out, "\"cipher_hash_input\":\"1301,1302,c02f\"") {
		t.Fatalf("expected cipher hash input in debug output, got %q", out)
	}
	if !strings.Contains(out, "\"ext_hash_input\":\"000d,002b_0403,0804\"") {
		t.Fatalf("expected ext hash input in debug output, got %q", out)
	}
	if stderr.Len() != 0 {
		t.Fatalf("did not expect stderr output: %q", stderr.String())
	}
}

func TestRunPCAPWritesToCustomLogFile(t *testing.T) {
	withWorkingDir(t, t.TempDir())
	path := writePCAPFixture(t, fullTLSClientHello())
	logPath := filepath.Join("nested", "ja4-results.log")
	var stdout, stderr bytes.Buffer

	if err := runWithContext(context.Background(), []string{"pcap", "--file", path, "--log-file", logPath}, &stdout, &stderr); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	logData, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("ReadFile(%q): %v", logPath, err)
	}
	if string(logData) != stdout.String() {
		t.Fatalf("expected custom log file to match stdout, got %q", string(logData))
	}
	if stderr.Len() != 0 {
		t.Fatalf("did not expect stderr output: %q", stderr.String())
	}
}

func TestRunPCAPReportsIncompleteTLSHandshakeToStderr(t *testing.T) {
	withWorkingDir(t, t.TempDir())
	path := writePCAPFixture(t, fullTLSClientHello()[:len(fullTLSClientHello())-1])
	var stdout, stderr bytes.Buffer

	if err := runWithContext(context.Background(), []string{"pcap", "--file", path}, &stdout, &stderr); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if stdout.Len() != 0 {
		t.Fatalf("did not expect fingerprint output: %q", stdout.String())
	}
	if !strings.Contains(stderr.String(), "incomplete TLS client hello") {
		t.Fatalf("expected incomplete handshake on stderr, got %q", stderr.String())
	}
}

func withWorkingDir(t *testing.T, dir string) {
	t.Helper()

	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd: %v", err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("Chdir(%q): %v", dir, err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(wd); err != nil {
			t.Fatalf("restore working directory: %v", err)
		}
	})
}

func writeLiveConfig(t *testing.T, contents string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "ja4finger.yaml")
	if err := os.WriteFile(path, []byte(contents), 0o644); err != nil {
		t.Fatalf("WriteFile(%q): %v", path, err)
	}
	return path
}

func writePCAPFixture(t *testing.T, payload []byte) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "fixture.pcap")
	file, err := os.Create(path)
	if err != nil {
		t.Fatalf("os.Create: %v", err)
	}
	defer file.Close()

	writer := pcapgo.NewWriter(file)
	if err := writer.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
		t.Fatalf("WriteFileHeader: %v", err)
	}

	packet := buildPacket(t, payload)
	if err := writer.WritePacket(gopacket.CaptureInfo{
		Timestamp:     time.Now(),
		CaptureLength: len(packet),
		Length:        len(packet),
	}, packet); err != nil {
		t.Fatalf("WritePacket: %v", err)
	}

	return path
}

func buildPacket(t *testing.T, payload []byte) []byte {
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
	return buf.Bytes()
}

func fullTLSClientHello() []byte {
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
