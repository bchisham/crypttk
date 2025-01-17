package types

import (
	"encoding/gob"
)

func init() {
	gob.Register(Container{})
}

type EncodingFunc func([]byte) ([]byte, error)

// Container is a signed block containing the IV, Length, Data, and HMAC
// The Length is the length of the original data before padding this value is encrypted and stored in the block
// The IV is the initialization vector used for encryption
// The Data is the encrypted data padded to the block size
// The HMAC is the hash of the IV, Length, and Data under the influence of the key
type Container struct {
	Iv     []byte
	Length []byte
	Data   []byte
	Hmac   []byte
}
