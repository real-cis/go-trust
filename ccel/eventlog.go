package ccel

import (
	"bufio"
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"log"
	"strconv"
	"strings"

	"gitlab.com/real-cis/cc/go-trust/internal/tcg"
)

type EventLogParser struct {
	RecNum    int
	ImrIndex  int
	EventType tcg.EventType
	Digests   []tcg.Digest
	EventSize int
	Event     []byte
}

func (p *EventLogParser) Format(format tcg.EventFormat) FormatedTcgEvent {
	switch format {
	case TCG_PCCLIENT_FORMAT:
		return p.formatTcgPCClient()
	case TCG_CANONICAL_FORMAT:
		return nil
	}
	return nil
}

func (p *EventLogParser) formatTcgPCClient() FormatedTcgEvent {
	if p.EventType == tcg.EvNoAction && p.RecNum == 0 && p.ImrIndex == 0 {
		event := &TcgPcClientImrEvent{
			ImrIndex:      uint32(p.ImrIndex),
			EventType:     p.EventType,
			EventDataSize: uint32(p.EventSize),
			Event:         p.Event,
			FormatType:    TCG_PCCLIENT_FORMAT,
		}
		copy(event.Digest[:], p.Digests[0].Hash)

		return event
	}

	return &ImrEvent{
		ImrIndex:   uint32(p.ImrIndex),
		EventType:  p.EventType,
		Digests:    p.Digests,
		EventSize:  uint32(p.EventSize),
		Event:      p.Event,
		FormatType: TCG_PCCLIENT_FORMAT,
	}
}

type FormatedTcgEvent interface {
	Dump()
	GetFormatType() tcg.EventFormat
	GetImrIndex() uint32
	GetEventType() tcg.EventType
	GetDigests() []tcg.Digest
}

var _ FormatedTcgEvent = (*ImrEvent)(nil)

type ImrEvent struct {
	ImrIndex   uint32
	EventType  tcg.EventType
	Digests    []tcg.Digest
	EventSize  uint32
	Event      []byte
	FormatType tcg.EventFormat
}

// GetDigests implements FormatedTcgEvent.
func (e *ImrEvent) GetDigests() []tcg.Digest {
	return e.Digests
}

// GetEventType implements FormatedTcgEvent.
func (e *ImrEvent) GetEventType() tcg.EventType {
	return e.EventType
}

// GetImrIndex implements FormatedTcgEvent.
func (e *ImrEvent) GetImrIndex() uint32 {
	return e.ImrIndex
}

// FormatType implements FormatedTcgEvent.
func (e *ImrEvent) GetFormatType() tcg.EventFormat {
	return e.FormatType
}

// Dump implements FormatedTcgEvent.
func (e *ImrEvent) Dump() {
	l := log.Default()
	l.Println("----------------------------------Event Log Entry---------------------------------")
	l.Printf("IMR               : %d\n", e.ImrIndex)
	l.Printf("Type              : 0x%X (%v)\n", uint32(e.EventType), e.EventType)
	count := 0
	for _, digest := range e.Digests {
		l.Printf("Algorithm_id[%d]   : %d (%v) \n", count, digest.AlgID, digest.AlgID)
		l.Printf("Digest[%d]:\n", count)
		digestBlob := NewBuffer(digest.Hash, 0)
		digestBlob.Dump()
		count += 1
	}
	l.Println("Event:")
	eventBlob := NewBuffer(e.Event, 0)
	eventBlob.Dump()
}

var _ FormatedTcgEvent = (*TcgPcClientImrEvent)(nil)

type TcgPcClientImrEvent struct {
	ImrIndex      uint32
	EventType     tcg.EventType
	Digest        [20]byte
	EventDataSize uint32
	Event         []byte
	FormatType    tcg.EventFormat
}

// GetDigests implements FormatedTcgEvent.
func (e *TcgPcClientImrEvent) GetDigests() []tcg.Digest {
	return nil
}

// GetEventType implements FormatedTcgEvent.
func (e *TcgPcClientImrEvent) GetEventType() tcg.EventType {
	return e.EventType
}

// GetImrIndex implements FormatedTcgEvent.
func (e *TcgPcClientImrEvent) GetImrIndex() uint32 {
	return e.ImrIndex
}

// FormatType implements FormatedTcgEvent.
func (e *TcgPcClientImrEvent) GetFormatType() tcg.EventFormat {
	return e.FormatType
}

// Dump implements FormatedTcgEvent.
func (e *TcgPcClientImrEvent) Dump() {
	l := log.Default()
	l.Println("--------------------Header Specification ID Event--------------------------")
	l.Printf("IMR               : %d\n", e.ImrIndex)
	l.Printf("Type              : 0x%X (%v) \n", uint32(e.EventType), e.EventType)
	l.Println("Digest:")
	digestBlob := NewBuffer(e.Digest[:], 0)
	digestBlob.Dump()
	l.Println("Event:")
	eventBlob := NewBuffer(e.Event, 0)
	eventBlob.Dump()
}

type TcgEfiSpecIdEventAlgorithmSize struct {
	AlgorithmId uint16
	DigestSize  uint16
}

type TcgEfiSpecIdEvent struct {
	Signature          [16]byte
	PlatformClass      uint32
	SpecVersionMinor   uint8
	SpecVersionMajor   uint8
	SpecErrata         uint8
	UintnSize          uint8
	NumberOfAlgorithms uint32
	DigestSizes        []TcgEfiSpecIdEventAlgorithmSize
	VendorInfoSize     uint8
	VendorInfo         []byte
}

type EventLogger struct {
	bootTimeLog       []byte
	runTimeLog        []byte
	imrCount          [24]int
	count             int
	eventFormat       tcg.EventFormat
	tcgEventLogs      []FormatedTcgEvent
	specIdHeaderEvent *TcgEfiSpecIdEvent
	isSelected        bool
}

func NewEventLogger(bootTimeLog, runTimeLog []byte, eventFormat tcg.EventFormat) *EventLogger {
	l := &EventLogger{
		bootTimeLog:  bootTimeLog,
		runTimeLog:   runTimeLog,
		eventFormat:  eventFormat,
		imrCount:     [24]int{},
		count:        0,
		tcgEventLogs: make([]FormatedTcgEvent, 0),
	}
	return l
}

func (l *EventLogger) Parse() error {
	if err := l.parseEventLog(); err != nil {
		return err
	}
	if err := l.parseIMALog(); err != nil {
		return err
	}
	return nil
}

func (l *EventLogger) Dump() {
	lg := log.Default()

	lg.Printf("Event Log Entries:\n")
	for _, el := range l.tcgEventLogs {
		el.Dump()
	}
}

func (l *EventLogger) Count() int {
	return l.count
}

func (l *EventLogger) IsSelected() bool {
	return l.isSelected
}

func (l *EventLogger) Select(start, count int) (*EventLogger, error) {
	if l.isSelected {
		return nil, errors.New("the eventlog is selected, can not be selected again")
	}
	if start < 0 || start >= l.count {
		return nil, fmt.Errorf("the start %d is out of valid range [%d, %d)", start, 0, l.count)
	}
	if count <= 0 || start+count >= l.count {
		return nil, fmt.Errorf("the count %d is <=0 or > %d the max valid count", 0, l.count-start)
	}

	l.tcgEventLogs = l.tcgEventLogs[start : start+count]
	l.isSelected = true
	return l, nil
}

func (l *EventLogger) EventLog() []FormatedTcgEvent {
	return l.tcgEventLogs
}

func ReplayFormatedEventLog(formatedEventLogs []FormatedTcgEvent) map[int]map[tcg.Algorithm][]byte {
	ret := make(map[int]map[tcg.Algorithm][]byte, 0)
	lg := log.Default()
	for _, event := range formatedEventLogs {
		if !isSupportedFormat(event) {
			lg.Println("event with unknown format. Skip this one...")
			continue
		}
		if event.GetEventType() == tcg.EvNoAction {
			continue
		}

		idx := int(event.GetImrIndex())
		if _, ok := ret[idx]; !ok {
			ret[idx] = make(map[tcg.Algorithm][]byte, 0)
		}

		for _, digest := range event.GetDigests() {
			var hash hash.Hash
			alg := digest.AlgID
			switch alg {
			case TPM_ALG_SHA1:
				hash = sha1.New()
			case TPM_ALG_SHA384:
				hash = sha512.New384()
			case TPM_ALG_SHA256:
				hash = sha256.New()
			case TPM_ALG_SHA512:
				hash = sha512.New()
			default:
				lg.Printf("Unsupported hash algorithm  %v\n", alg)
				continue
			}

			val := make([]byte, tcg.DigestSizeTable[alg])
			if b, ok := ret[idx][alg]; !ok {
				ret[idx][alg] = make([]byte, 0)
			} else {
				val = b
			}
			hash.Write(append(val, digest.Hash...))
			ret[idx][alg] = hash.Sum(nil)
		}

	}
	return ret
}

func (l *EventLogger) Replay() map[int]map[tcg.Algorithm][]byte {
	return ReplayFormatedEventLog(l.tcgEventLogs)
}

func isSupportedFormat(e FormatedTcgEvent) bool {
	switch e.GetFormatType() {
	case TCG_PCCLIENT_FORMAT:
		fallthrough
	case TCG_CANONICAL_FORMAT:
		return true
	}
	return false
}

type EventLogBlob struct {
	Buffer
}

func NewEventLogBlob(b []byte) EventLogBlob {
	return EventLogBlob{
		Buffer{b, 0},
	}
}

func (b *EventLogBlob) Meta(start int) (uint32, tcg.EventType, int, error) {
	imr, idx := b.ParseUint32(start)
	eventType, idx := b.ParseUint32(idx)
	return imr, tcg.EventType(eventType), idx, nil
}

func (b *EventLogBlob) ParseSpecIdEventLog(start, recNum, imr int, eventType tcg.EventType) (*EventLogParser, *TcgEfiSpecIdEvent, int, error) {
	hash, idx := b.ParseBytes(start, 20)
	digest := tcg.NewDigest(tcg.AlgSHA1, hash)
	headerEventSize, idx := b.ParseUint32(idx)
	headerEvent, _ := b.ParseBytes(idx, int(headerEventSize))

	specificationIdHeader := &EventLogParser{
		RecNum:    recNum,
		ImrIndex:  imr - 1,
		EventType: eventType,
		Digests:   []tcg.Digest{digest},
		EventSize: int(headerEventSize),
		Event:     headerEvent,
	}

	// Parse EFI Spec Id Event structure
	specIdEvent, idx, err := b.parseEFISpecIdEvent(idx)
	if err != nil {
		return nil, nil, idx, err
	}
	return specificationIdHeader, specIdEvent, idx, nil
}

func (b *EventLogBlob) ParseEventLog(start, recNum, imr int, eventType tcg.EventType, digestSizes []TcgEfiSpecIdEventAlgorithmSize) (*EventLogParser, int, error) {
	cnt, idx := b.ParseUint32(start)
	digests := make([]tcg.Digest, 0)
	for i := uint32(0); i < cnt; i++ {
		algId, next := b.ParseUint16(idx)
		size := findDigestSize(algId, digestSizes)
		hash, next := b.ParseBytes(next, int(size))
		digests = append(digests, tcg.NewDigest(tcg.Algorithm(algId), hash))
		idx = next
	}
	eventSize, idx := b.ParseUint32(idx)
	eventBytes, idx := b.ParseBytes(idx, int(eventSize))
	event := &EventLogParser{
		RecNum:    recNum,
		ImrIndex:  imr - 1,
		EventType: eventType,
		Digests:   digests,
		EventSize: int(eventSize),
		Event:     eventBytes,
	}
	return event, idx, nil
}

func findDigestSize(algId uint16, digestSizes []TcgEfiSpecIdEventAlgorithmSize) uint16 {
	for _, elem := range digestSizes {
		if elem.AlgorithmId == algId {
			return elem.DigestSize
		}
	}
	return 0
}

func (b *EventLogBlob) parseEFISpecIdEvent(start int) (*TcgEfiSpecIdEvent, int, error) {
	signature, idx := b.ParseBytes(start, 16)
	platformCls, idx := b.ParseUint32(idx)
	versionMajor, idx := b.ParseUint8(idx)
	versionMinor, idx := b.ParseUint8(idx)
	errata, idx := b.ParseUint8(idx)
	uintSize, idx := b.ParseUint8(idx)
	numOfAlgo, idx := b.ParseUint32(idx)
	digestSizes := make([]TcgEfiSpecIdEventAlgorithmSize, 0)
	for i := uint32(0); i < numOfAlgo; i++ {
		algoId, next := b.ParseUint16(idx)
		size, next := b.ParseUint16(next)
		digestSizes = append(digestSizes, TcgEfiSpecIdEventAlgorithmSize{
			AlgorithmId: algoId,
			DigestSize:  size,
		})
		idx = next
	}
	vendorSize, idx := b.ParseUint8(idx)
	vendorInfo, idx := b.ParseBytes(idx, int(vendorSize))

	event := &TcgEfiSpecIdEvent{
		PlatformClass:      platformCls,
		SpecVersionMinor:   versionMajor,
		SpecVersionMajor:   versionMinor,
		SpecErrata:         errata,
		UintnSize:          uintSize,
		NumberOfAlgorithms: numOfAlgo,
		DigestSizes:        digestSizes,
		VendorInfoSize:     vendorSize,
		VendorInfo:         vendorInfo,
	}
	copy(event.Signature[:], signature)

	return event, idx, nil
}

func (l *EventLogger) getRecordNumber(imr int) int {
	cnt := l.imrCount[imr]
	l.imrCount[imr]++
	return cnt
}

func (l *EventLogger) parseEventLog() error {
	blob := NewEventLogBlob(l.bootTimeLog)
	idx := 0
	length := len(l.bootTimeLog)
	for idx < length {
		imr, eventType, next, err := blob.Meta(idx)
		idx = next
		if err != nil {
			return err
		}
		if imr == 0xFFFFFFFF {
			break
		}
		var parser *EventLogParser
		recNum := l.getRecordNumber(int(imr - 1))
		if eventType == tcg.EvNoAction && l.count == 0 {
			specIdEventParser, specIdEvent, next, err :=
				blob.ParseSpecIdEventLog(idx, recNum, int(imr), eventType)
			if err != nil {
				return err
			}
			parser = specIdEventParser
			idx = next
			l.specIdHeaderEvent = specIdEvent
		} else {
			eventParser, next, err :=
				blob.ParseEventLog(idx, recNum, int(imr), eventType, l.specIdHeaderEvent.DigestSizes)
			if err != nil {
				return err
			}
			parser = eventParser
			idx = next
		}

		if parser == nil {
			break
		}
		formatedLog := parser.Format(l.eventFormat)
		l.tcgEventLogs = append(l.tcgEventLogs, formatedLog)
		l.count++
	}

	return nil
}

type IMALogBlob struct {
	Buffer
	*bufio.Scanner
}

func NewIMALogBlob(b []byte) IMALogBlob {
	blob := IMALogBlob{
		Buffer: Buffer{b, 0},
	}
	r := bytes.NewReader(blob.ByteArray)
	s := bufio.NewScanner(r)
	blob.Scanner = s
	return blob
}

func (b *IMALogBlob) ParseLine(line []byte) (*EventLogParser, error) {
	elements := strings.Split(string(line), " ")

	if len(elements) < 4 {
		return nil, errors.New("unrecognized ima log: " + string(line))
	}
	imrIdx, err := strconv.Atoi(elements[0])
	if err != nil {
		return nil, err
	}

	hexDigest := elements[1]
	lenOfDigest := len(hexDigest) / 2
	algId := tcg.AlgError
	for k, v := range tcg.DigestSizeTable {
		if lenOfDigest == v {
			algId = k
			break
		}
	}

	digest := tcg.NewDigest(algId, make([]byte, lenOfDigest))
	hash, err := hex.DecodeString(hexDigest)
	if err != nil {
		return nil, err
	}
	copy(digest.Hash, hash)

	event := []byte(strings.Join(elements[3:], " "))
	eventSize := len(event)

	parser := &EventLogParser{
		RecNum:    -1,
		ImrIndex:  imrIdx,
		EventType: tcg.EvIMAMeasurementEvent,
		Digests:   []tcg.Digest{digest},
		EventSize: eventSize,
		Event:     event,
	}
	return parser, nil
}

func (l *EventLogger) parseIMALog() error {
	if len(l.runTimeLog) <= 0 {
		return nil
	}
	blob := NewIMALogBlob(l.runTimeLog)
	for blob.Scan() {
		line := bytes.TrimSpace(blob.Bytes())
		parser, err := blob.ParseLine(line)
		if err != nil {
			return err
		}

		recNum := l.getRecordNumber(parser.ImrIndex)
		parser.RecNum = recNum
		l.tcgEventLogs = append(l.tcgEventLogs, parser.Format(l.eventFormat))
	}
	return nil
}
