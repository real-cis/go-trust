package sgx

import (
	"testing"
)

func TestEvaluateTCBLevel(t *testing.T) {
	tcbInfo := &TCBInfo{
		TCBLevels: []TCBLevel{
			{
				TCBStatus: "UpToDate",
				TCB: TCBComponents{
					PCESVN: 5,
					SGXTCBComponents: func() []TCBComponent {
						comps := make([]TCBComponent, 16)
						for i := range comps {
							comps[i] = TCBComponent{SVN: 2}
						}
						return comps
					}(),
				},
			},
			{
				TCBStatus: "OutOfDate",
				TCB: TCBComponents{
					PCESVN: 3,
					SGXTCBComponents: func() []TCBComponent {
						comps := make([]TCBComponent, 16)
						for i := range comps {
							comps[i] = TCBComponent{SVN: 1}
						}
						return comps
					}(),
				},
			},
		},
	}

	tests := []struct {
		name       string
		cpusvn     [16]byte
		pcesvn     int
		wantStatus string
	}{
		{
			name:       "matches UpToDate level",
			cpusvn:     [16]byte{3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3},
			pcesvn:     5,
			wantStatus: "UpToDate",
		},
		{
			name:       "matches OutOfDate level",
			cpusvn:     [16]byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1},
			pcesvn:     3,
			wantStatus: "OutOfDate",
		},
		{
			name:       "no match returns Revoked",
			cpusvn:     [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
			pcesvn:     0,
			wantStatus: "Revoked",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			status, _ := tcbInfo.evaluateTCBLevel(tc.cpusvn, tc.pcesvn)
			if status != tc.wantStatus {
				t.Errorf("got status %q, want %q", status, tc.wantStatus)
			}
		})
	}
}
