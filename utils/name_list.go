package utils

import (
	"bytes"
	"encoding/binary"
	"io"
	"strings"
)

type NameList []string

func (n NameList) Marshal() []byte {
	s := strings.Join(n, ",")

	buf := new(bytes.Buffer)

	length := len(s)
	binary.Write(buf, binary.BigEndian, uint32(length))

	if length > 0 {
		buf.WriteString(s)
	}

	return buf.Bytes()
}

func UnmarshalNamelist(data []byte) (NameList, int, error) {
	if len(data) < 4 {
		return nil, 0, io.ErrUnexpectedEOF
	}

	length := binary.BigEndian.Uint32(data[:4])
	if len(data) < int(length)+4 {
		return nil, 0, io.ErrUnexpectedEOF
	}

	raw := string(data[4 : 4+length])
	if raw == "" {
		return NameList{}, 0, nil
	}

	return strings.Split(raw, ","), int(4 + length), nil
}
