package edns

import "encoding/base64"

func decodeGETQuery(value string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(value)
}
