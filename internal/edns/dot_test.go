package edns

import (
	"bytes"
	"encoding/binary"
	"testing"
)

type scriptedReadWriter struct {
	read    *bytes.Reader
	written bytes.Buffer
}

func (stream *scriptedReadWriter) Read(payload []byte) (int, error) {
	return stream.read.Read(payload)
}

func (stream *scriptedReadWriter) Write(payload []byte) (int, error) {
	return stream.written.Write(payload)
}

func TestExchangeTCPFrame(t *testing.T) {
	responsePayload := []byte{9, 8, 7}
	framedResponse := make([]byte, 2+len(responsePayload))
	binary.BigEndian.PutUint16(framedResponse[:2], uint16(len(responsePayload)))
	copy(framedResponse[2:], responsePayload)
	stream := &scriptedReadWriter{read: bytes.NewReader(framedResponse)}

	query := []byte{1, 2, 3, 4}
	response, err := exchangeTCPFrame(stream, query)
	if err != nil {
		t.Fatalf("exchange TCP frame: %v", err)
	}
	if !bytes.Equal(response, responsePayload) {
		t.Fatalf("response = %v, want %v", response, responsePayload)
	}
	written := stream.written.Bytes()
	if int(binary.BigEndian.Uint16(written[:2])) != len(query) || !bytes.Equal(written[2:], query) {
		t.Fatalf("invalid query frame: %v", written)
	}
}
