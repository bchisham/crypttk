package blocks

import (
	"encoding/base64"
	"encoding/hex"
)

func NoEncoding(data []byte) ([]byte, error) {
	return data, nil
}
func HexEncoding(data []byte) ([]byte, error) {
	dst := make([]byte, hex.EncodedLen(len(data)))
	hex.Encode(dst, data)
	return dst, nil
}

func HexDecoding(data []byte) ([]byte, error) {
	dst := make([]byte, hex.DecodedLen(len(data)))
	n, err := hex.Decode(dst, data)
	if err != nil {
		return nil, err
	}
	return dst[:n], nil
}

func Base64Encoding(data []byte) ([]byte, error) {
	dst := make([]byte, base64.StdEncoding.EncodedLen(len(data)))
	base64.StdEncoding.Encode(dst, data)
	return dst, nil
}

func Base64Decoding(data []byte) ([]byte, error) {
	dst := make([]byte, base64.StdEncoding.DecodedLen(len(data)))
	n, err := base64.StdEncoding.Decode(dst, data)
	if err != nil {
		return nil, err
	}
	return dst[:n], nil
}
