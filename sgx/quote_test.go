package sgx

import (
	"encoding/hex"
	"os"
	"testing"
	"time"
)

type quoteTestCase struct {
	name string
	file string

	// Static values – embedded in the quote binary, stable across Intel TCB updates.
	wantFMSPC     string
	wantMRENCLAVE string
	wantMRSIGNER  string
	wantCPUSVN    string
	wantPCESVN    uint16

	// wantTCBStatus is the TCB evaluation result observed when calling Intel PCS
	// as on 2026-02-20.  If Intel issues a new TCB update that changes this value,
	// update the field below.
	wantTCBStatus string
}

var quoteTestCases []quoteTestCase

func TestParseQuote_PrintStaticValues(t *testing.T) {
	files := []string{
		"testdata/quote.emerald-rapids.20260220.bin",
		"testdata/quote.ice-lake-hyperthreading.20260220.bin",
		"testdata/quote.ice-lake-no-hyperthreading.20260220.bin",
	}
	for _, f := range files {
		f := f
		t.Run(f, func(t *testing.T) {
			data, err := os.ReadFile(f)
			if err != nil {
				t.Skipf("skipping: %v", err)
			}
			q, err := ParseQuote(data)
			if err != nil {
				t.Fatalf("ParseQuote: %v", err)
			}
			fmspc, err := q.FMSPC()
			if err != nil {
				t.Logf("FMSPC error: %v", err)
			}
			t.Logf("File:      %s", f)
			t.Logf("Version:   %d", q.Version)
			t.Logf("FMSPC:     %s", fmspc)
			t.Logf("MRENCLAVE: %s", hex.EncodeToString(q.ReportBody.MrEnclave[:]))
			t.Logf("MRSIGNER:  %s", hex.EncodeToString(q.ReportBody.MrSigner[:]))
			t.Logf("CPUSVN:    %s", hex.EncodeToString(q.ReportBody.CPUSVN[:]))
			t.Logf("PCESVN:    %d", q.PCESVN)
			t.Logf("ISVProdID: %d", q.ReportBody.ISVProdID)
			t.Logf("ISVSVN:    %d", q.ReportBody.ISVSVN)
		})
	}
}

func init() {
	quoteTestCases = []quoteTestCase{
		{
			name:          "emerald-rapids",
			file:          "testdata/quote.emerald-rapids.20260220.bin",
			wantFMSPC:     "B0C06F000000",
			wantMRENCLAVE: "a2d1e398461c7d5876ecf8bf1cfd0c51af718d3d844eb1ed70df5b5571903d48",
			wantMRSIGNER:  "66d07b620a0ddd1f53f55b60fc22294481d572cfb8a709f570b6a82ae26b197c",
			wantCPUSVN:    "0303191b04ff00060000000000000000",
			wantPCESVN:    16,
			wantTCBStatus: "UpToDate",
		},
		{
			name:          "ice-lake-hyperthreading",
			file:          "testdata/quote.ice-lake-hyperthreading.20260220.bin",
			wantFMSPC:     "30606A000000",
			wantMRENCLAVE: "5f7cb6f489bdca2ea9f5a708e26f1bbbe12c6fbc1384b1fa3de2c45458bc56fa",
			wantMRSIGNER:  "250bfda182de58e14f106893942cc3ba3b00c2cb751ca64c8f99c9395be026c0",
			wantCPUSVN:    "10101110ffff00000000000000000000",
			wantPCESVN:    16,
			wantTCBStatus: "ConfigurationAndSWHardeningNeeded",
		},
		{
			name:          "ice-lake-no-hyperthreading",
			file:          "testdata/quote.ice-lake-no-hyperthreading.20260220.bin",
			wantFMSPC:     "30606A000000",
			wantMRENCLAVE: "3e46e5375015d9c1d7fddec92c284e089b02cc0bc05499d13a0a9990522b534e",
			wantMRSIGNER:  "a2f440887d747e2cec824f2dccc7537b686b523eba7582894897910dd5e14b14",
			wantCPUSVN:    "10101110ffff01000000000000000000",
			wantPCESVN:    16,
			wantTCBStatus: "SWHardeningNeeded",
		},
	}
}

// verifies only those assertions that are stable across Intel TCB updates
func TestParseQuote(t *testing.T) {
	for _, tc := range quoteTestCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			data, err := os.ReadFile(tc.file)
			if err != nil {
				t.Fatalf("ReadFile(%q): %v", tc.file, err)
			}

			q, err := ParseQuote(data)
			if err != nil {
				t.Fatalf("ParseQuote: %v", err)
			}

			if q.QuoteType != QuoteSGX {
				t.Errorf("QuoteType = %v, want QuoteSGX", q.QuoteType)
			}
			if q.Version != QuoteVersion3 {
				t.Errorf("Version = %d, want %d", q.Version, QuoteVersion3)
			}

			fmspc, err := q.FMSPC()
			if err != nil {
				t.Fatalf("FMSPC: %v", err)
			}
			if tc.wantFMSPC != "" && fmspc != tc.wantFMSPC {
				t.Errorf("FMSPC = %q, want %q", fmspc, tc.wantFMSPC)
			}

			gotMRENCLAVE := hex.EncodeToString(q.ReportBody.MrEnclave[:])
			if tc.wantMRENCLAVE != "" && gotMRENCLAVE != tc.wantMRENCLAVE {
				t.Errorf("MRENCLAVE = %q, want %q", gotMRENCLAVE, tc.wantMRENCLAVE)
			}

			gotMRSIGNER := hex.EncodeToString(q.ReportBody.MrSigner[:])
			if tc.wantMRSIGNER != "" && gotMRSIGNER != tc.wantMRSIGNER {
				t.Errorf("MRSIGNER = %q, want %q", gotMRSIGNER, tc.wantMRSIGNER)
			}

			gotCPUSVN := hex.EncodeToString(q.ReportBody.CPUSVN[:])
			if tc.wantCPUSVN != "" && gotCPUSVN != tc.wantCPUSVN {
				t.Errorf("CPUSVN = %q, want %q", gotCPUSVN, tc.wantCPUSVN)
			}

			if tc.wantPCESVN != 0 && q.PCESVN != tc.wantPCESVN {
				t.Errorf("PCESVN = %d, want %d", q.PCESVN, tc.wantPCESVN)
			}
		})
	}
}

func TestVerify_Integration(t *testing.T) {

	client := NewPCSClient(
		"https://pccs.svc.bit-heat.com",
		"",
		10*time.Second,
	)

	for _, tc := range quoteTestCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			data, err := os.ReadFile(tc.file)
			if err != nil {
				t.Fatalf("ReadFile(%q): %v", tc.file, err)
			}

			q, err := ParseQuote(data)
			if err != nil {
				t.Fatalf("ParseQuote: %v", err)
			}

			result, err := (&QuoteVerifier{Quote: q, Client: client}).Verify()
			if err != nil {
				t.Fatalf("Verify: %v", err)
			}

			t.Logf("TCBStatus=%s AdvisoryIDs=%v", result.TCBLevel, result.AdvisoryIDs)

			if result.TCBLevel != tc.wantTCBStatus {
				t.Errorf(
					"TCBStatus = %q, want %q\n"+
						"NOTE: Intel might have a TCB update .\n"+
						"If the new status is expected, update wantTCBStatus in quoteTestCases.",
					result.TCBLevel, tc.wantTCBStatus,
				)
			}
		})
	}
}
