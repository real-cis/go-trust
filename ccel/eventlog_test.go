package ccel

import (
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEventLog(t *testing.T) {
	elBin, err := os.ReadFile("testdata/CCEL.1")
	assert.Nil(t, err)

	el := NewEventLogger(elBin, nil, TCG_PCCLIENT_FORMAT)
	e := el.Parse()
	assert.Nil(t, e)

	// fmt.Printf("Parse event log %v \n", el.EventLog())
	// for _, fel := range el.EventLog() {
	// 	fel.Dump()
	// }

	replayMap := el.Replay()
	fmt.Printf("Replay: %v \n", replayMap)

	// compare rtmr0 value with expected
	expectedRtmr0 := []byte{201, 19, 73, 163, 21, 80, 119, 95, 162, 255, 14, 58, 53, 121, 73, 50,
		10, 161, 38, 128, 206, 40, 155, 223, 12, 105, 102, 179, 200, 3, 255, 234,
		198, 52, 75, 184, 161, 223, 214, 15, 191, 90, 7, 218, 28, 168, 36, 197,
	}
	rtmr0 := replayMap[0][TPM_ALG_SHA384]
	assert.Equal(t, expectedRtmr0, rtmr0)

}
