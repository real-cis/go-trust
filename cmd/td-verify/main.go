// Command td-verify checks the attestation evidence published for a
// Betteredge Trusted Execution Domain.
//
// Only --quote is required: it is the hardware-signed root of everything else.
// Each further artefact enables further checks, and anything not supplied is
// reported as skipped rather than silently passed.
//
//	td-verify --quote quote.dat
//	td-verify --quote quote.dat --firmware OVMF.fd --ccel ccel.bin
package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"strings"

	pb "github.com/google/go-tdx-guest/proto/tdx"
	"gitlab.com/real-cis/cc/go-trust/ccel"
	"gitlab.com/real-cis/cc/go-trust/pkg/tcg"
	"gitlab.com/real-cis/cc/go-trust/pkg/uefi"
	"gitlab.com/real-cis/cc/go-trust/tdvf"
	"gitlab.com/real-cis/cc/go-trust/tdx"
)

const teeTypeTDX = 0x81

var passed, failed, skipped int

// Report

func section(title string)   { fmt.Printf("\n== %s ==\n", title) }
func note(key, value string) { fmt.Printf("       %-20s %s\n", key, value) }

func status(kind, name string, detail ...string) {
	line := fmt.Sprintf("[%s] %s", kind, name)
	if d := strings.Join(detail, " "); d != "" {
		line += "  " + d
	}
	fmt.Println(line)
}

func pass(name string, detail ...string) { passed++; status("PASS", name, detail...) }
func fail(name string, detail ...string) { failed++; status("FAIL", name, detail...) }
func skip(name string, detail ...string) { skipped++; status("SKIP", name, detail...) }

func verdict(ok bool, name string, detail ...string) {
	if ok {
		pass(name, detail...)
		return
	}
	fail(name, detail...)
}

func die(err error) {
	fmt.Fprintf(os.Stderr, "error: %v\n", err)
	os.Exit(2)
}

// Helpers

func isZero(b []byte) bool {
	return len(b) > 0 && bytes.Equal(b, make([]byte, len(b)))
}

func isNetworkError(err error) bool {
	s := strings.ToLower(err.Error())
	for _, needle := range []string{"dial", "timeout", "no such host",
		"connection refused", "network is unreachable"} {
		if strings.Contains(s, needle) {
			return true
		}
	}
	return false
}

func sha384(digests []tcg.Digest) []byte {
	for _, d := range digests {
		if d.AlgID == tcg.AlgSHA384 {
			return d.Hash
		}
	}
	return nil
}

// normalizeRTMRs maps replayed register indices onto RTMR numbers.
func normalizeRTMRs(in map[int][]byte) map[int][]byte {
	if _, direct := in[0]; direct {
		return in
	}
	out := make(map[int][]byte, len(in))
	for k, v := range in {
		if k >= 1 {
			out[k-1] = v
		}
	}
	return out
}

// Platform

// checkPlatform runs the signature, PCK chain, revocation and TCB checks.
func checkPlatform(p tdx.QuoteProvider, raw []byte, skipSig bool) (offline bool) {
	section("Platform")
	const name = "quote signature, PCK chain, revocation and TCB level"
	if skipSig {
		skip(name, "--skip-signature")
		return false
	}
	switch err := p.Verify(raw); {
	case err == nil:
		pass(name)
	case isNetworkError(err):
		skip(name, err.Error())
		return true
	default:
		fail(name, err.Error())
	}
	return false
}

// Quote body

var tdAttrBits = []struct {
	bit  uint
	name string
}{
	{0, "DEBUG"}, {28, "SEPT_VE_DISABLE"}, {29, "MIGRATABLE"},
	{30, "PKS"}, {31, "KL"}, {63, "PERFMON"},
}

func checkQuote(q *pb.QuoteV4, nonce string) {
	b := q.GetTdQuoteBody()
	section("Quote")
	note("version", fmt.Sprintf("v%d", q.GetHeader().GetVersion()))
	note("TEE_TCB_SVN", hex.EncodeToString(b.GetTeeTcbSvn()))
	note("MRSEAM", hex.EncodeToString(b.GetMrSeam()))
	note("MRTD", hex.EncodeToString(b.GetMrTd()))
	for i, v := range b.GetRtmrs() {
		note(fmt.Sprintf("RTMR%d", i), hex.EncodeToString(v))
	}
	note("reportData", hex.EncodeToString(b.GetReportData()))

	var attrs uint64
	if a := b.GetTdAttributes(); len(a) >= 8 {
		attrs = binary.LittleEndian.Uint64(a[:8])
	}
	var set []string
	for _, a := range tdAttrBits {
		if attrs&(1<<a.bit) != 0 {
			set = append(set, a.name)
		}
	}
	note("TD_ATTRIBUTES", fmt.Sprintf("0x%016x  %s", attrs, strings.Join(set, " ")))
	if x := b.GetXfam(); len(x) >= 8 {
		note("XFAM", fmt.Sprintf("0x%016x", binary.LittleEndian.Uint64(x[:8])))
	}

	verdict(q.GetHeader().GetTeeType() == teeTypeTDX, "quote is a TDX quote")
	verdict(attrs&1 == 0, "TD debug mode off (TD_ATTRIBUTES.DEBUG)")
	verdict(isZero(b.GetMrSignerSeam()), "TDX module is Intel-signed (MRSIGNERSEAM all-zero)")
	verdict(isZero(b.GetMrConfigId()) && isZero(b.GetMrOwner()) && isZero(b.GetMrOwnerConfig()),
		"MRCONFIGID, MROWNER and MROWNERCONFIG unset")

	const name = "reportData binds a caller-supplied challenge"
	switch {
	case nonce == "":
		skip(name, "no --nonce given")
	default:
		want, err := hex.DecodeString(strings.TrimSpace(nonce))
		if err != nil {
			fail(name, "--nonce is not valid hex")
			return
		}
		if n := len(b.GetReportData()); len(want) < n {
			want = append(want, make([]byte, n-len(want))...)
		}
		verdict(bytes.Equal(want, b.GetReportData()), name)
	}
}

// Event log

type logFacts struct {
	cfvDigest  []byte
	secureBoot map[string][]byte // variable name -> event digest
}

func checkEventLog(path string, q *pb.QuoteV4, verbose bool) (*logFacts, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	logger := ccel.NewEventLogger(raw, nil, tcg.PCClientFormat)
	if err := logger.Parse(); err != nil {
		return nil, fmt.Errorf("parse event log: %w", err)
	}

	section("Event log")
	note("events", fmt.Sprintf("%d", logger.Count()))

	summary := logger.Summary()
	if verbose {
		for _, e := range summary.Events {
			note(fmt.Sprintf("  MR%d %s", e.RTMRIndex, e.EventType), hex.EncodeToString(e.Digest))
		}
	}

	replayed := normalizeRTMRs(summary.RTMRs)
	quoted := q.GetTdQuoteBody().GetRtmrs()
	for i := 0; i < 3; i++ {
		name := fmt.Sprintf("RTMR%d replay matches quote", i)
		got, ok := replayed[i]
		if !ok || i >= len(quoted) {
			fail(name, "register missing from the log or the quote")
			continue
		}
		note(fmt.Sprintf("replayed RTMR%d", i), hex.EncodeToString(got))
		verdict(bytes.Equal(got, quoted[i]), name)
	}
	if len(quoted) > 3 && !isZero(quoted[3]) {
		note("RTMR3", "non-zero: extended at runtime, not covered by the boot log")
	}

	facts := &logFacts{secureBoot: map[string][]byte{}}
	sbEnabled := false
	sbFound := false
	for _, e := range logger.FilterByEventType([]tcg.EventType{tcg.EvEfiVariableDriverConfig}) {
		v, err := uefi.NewUefiVariableDataFromBytes(e.GetEvent())
		if err != nil || v.Name == nil {
			continue
		}
		name := v.Name.String()
		facts.secureBoot[name] = sha384(e.GetDigests())
		if strings.EqualFold(name, "SecureBoot") {
			sbFound = true
			sbEnabled = len(v.Data) > 0 && v.Data[0] == 1
		}
	}
	if !sbFound {
		fail("secure boot enabled (SecureBoot variable = 1)", "variable not present in the log")
	} else {
		verdict(sbEnabled, "secure boot enabled (SecureBoot variable = 1)")
	}
	for _, name := range []string{"PK", "KEK", "db", "dbx"} {
		if d, ok := facts.secureBoot[name]; ok {
			note(name, hex.EncodeToString(d))
		} else {
			note(name, "not present in the log")
		}
	}

	for _, e := range logger.FilterByEventType([]tcg.EventType{tcg.EvEfiPlatformFirmwareBlob2}) {
		if d := sha384(e.GetDigests()); d != nil {
			facts.cfvDigest = d
		}
	}
	if facts.cfvDigest != nil {
		note("CFV digest (log)", hex.EncodeToString(facts.cfvDigest))
	}
	return facts, nil
}

// Firmware

func checkFirmware(path string, qemuCompat bool, q *pb.QuoteV4, l *logFacts) error {
	m, err := tdvf.MeasureFirmware(path, qemuCompat)
	if err != nil {
		return err
	}

	section("Firmware")
	note("MRTD (computed)", hex.EncodeToString(m.GetMRTD()))
	note("CFV digest (image)", hex.EncodeToString(m.GetCFV()))

	// QEMU changed how TDVF sections are page-added after 8.x (qemu-tdx#1)
	if bytes.Equal(m.GetMRTD(), q.GetTdQuoteBody().GetMrTd()) {
		pass("MRTD of the firmware image matches the quote")
	} else {
		hint := "retry with --qemu-compat=false on QEMU 10.x hosts"
		if !qemuCompat {
			hint = "retry with --qemu-compat=true on QEMU 8.x hosts"
		}
		fail("MRTD of the firmware image matches the quote", hint)
	}

	if l == nil {
		skip("CFV digest matches the event log", "no --ccel given")
		skip("secure boot variables match the firmware image", "no --ccel given")
		return nil
	}

	if l.cfvDigest == nil {
		fail("CFV digest matches the event log", "no firmware blob event in RTMR0")
	} else {
		verdict(bytes.Equal(m.GetCFV(), l.cfvDigest), "CFV digest matches the event log")
	}

	sb := m.GetSecureBoot()
	var differ, absent []string
	for _, p := range []struct {
		name  string
		image []byte
	}{{"PK", sb.PK}, {"KEK", sb.KEK}, {"db", sb.DB}, {"dbx", sb.DBX}} {
		logged, ok := l.secureBoot[p.name]
		switch {
		case !ok || logged == nil:
			absent = append(absent, p.name)
		case !bytes.Equal(p.image, logged):
			differ = append(differ, p.name)
		}
	}
	const name = "secure boot variables match the firmware image"
	switch {
	case len(differ) > 0:
		fail(name, "differ: "+strings.Join(differ, ", "))
	case len(absent) == 4:
		skip(name, "none present in the log")
	case len(absent) > 0:
		pass(name, "not in log: "+strings.Join(absent, ", "))
	default:
		pass(name)
	}
	return nil
}

// Main

func main() {
	fs := flag.NewFlagSet("td-verify", flag.ExitOnError)
	quotePath := fs.String("quote", "", "path to the TDX quote (required)")
	fwPath := fs.String("firmware", "", "path to the TDVF/OVMF image")
	ccelPath := fs.String("ccel", "", "path to the CC event log")
	nonce := fs.String("nonce", "", "hex challenge expected in reportData")
	qemuCompat := fs.Bool("qemu-compat", true, "measure MRTD the way QEMU 8.x adds TDVF pages")
	skipSig := fs.Bool("skip-signature", false, "skip the signature, PCK chain and TCB checks")
	verbose := fs.Bool("verbose", false, "list every replayed event")
	if err := fs.Parse(os.Args[1:]); err != nil {
		os.Exit(2)
	}
	if *quotePath == "" {
		fmt.Fprintln(os.Stderr, "error: --quote is required")
		fs.Usage()
		os.Exit(2)
	}

	raw, err := os.ReadFile(*quotePath)
	if err != nil {
		die(err)
	}
	provider := tdx.NewQuoteProvider()
	quote, err := provider.Parse(raw)
	if err != nil {
		die(fmt.Errorf("parse quote: %w", err))
	}
	if quote.GetTdQuoteBody() == nil {
		die(fmt.Errorf("quote carries no TD report body"))
	}

	offline := checkPlatform(provider, raw, *skipSig)
	checkQuote(quote, *nonce)

	var facts *logFacts
	if *ccelPath == "" {
		section("Event log")
		skip("event log replay and secure boot state", "no --ccel given")
	} else if facts, err = checkEventLog(*ccelPath, quote, *verbose); err != nil {
		die(err)
	}

	if *fwPath == "" {
		section("Firmware")
		skip("firmware measurements", "no --firmware given")
	} else if err := checkFirmware(*fwPath, *qemuCompat, quote, facts); err != nil {
		die(err)
	}

	fmt.Printf("\n%d passed, %d failed, %d skipped\n", passed, failed, skipped)
	if skipped > 0 {
		fmt.Println("skipped checks prove nothing: coverage is partial")
	}
	switch {
	case failed > 0:
		os.Exit(1)
	case offline:
		os.Exit(3)
	}
}
