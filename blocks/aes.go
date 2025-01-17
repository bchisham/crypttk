package blocks

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/gob"
	"errors"
	"github.com/bchisham/crypttk/blocks/types"
	"strconv"
	"strings"
)

// Encrypt encrypts the data using the key and returns the signed block containing the data
// The signed block contains the IV, Length, Data, and HMAC
// The Length is the length of the original data before padding this value is encrypted and stored in the block
// The IV is the initialization vector used for encryption
// The Data is the encrypted data padded to the block size
// The HMAC is the hash of the IV, Length, and Data under the influence of the key
func Encrypt(data []byte, key []byte) (signedBlock types.Container, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return types.Container{}, err
	}
	clearLength := make([]byte, block.BlockSize())
	copy(clearLength, strconv.Itoa(len(data)))
	signedBlock.Length = make([]byte, block.BlockSize())
	copy(signedBlock.Length, clearLength)

	if len(data)%block.BlockSize() != 0 {
		padding := block.BlockSize() - len(data)%block.BlockSize()
		pdata := make([]byte, len(data)+padding)
		copy(pdata, data)
		data = pdata
	}

	signedBlock.Iv = make([]byte, block.BlockSize())
	signedBlock.Data = make([]byte, len(data))
	if _, err := rand.Read(signedBlock.Iv); err != nil {
		return types.Container{}, err
	}

	mode := cipher.NewCBCEncrypter(block, signedBlock.Iv)
	mode.CryptBlocks(signedBlock.Length, clearLength)
	mode.CryptBlocks(signedBlock.Data, data)

	signedBlock, err = signContainer(signedBlock, key)
	if err != nil {
		return types.Container{}, err
	}
	return signedBlock, nil
}

// Decrypt decrypts the signed block using the key and returns the data,
// If the HMAC does not match, an error is returned
// If the original length of the data is not a valid integer, an error is returned
func Decrypt(signedBlock types.Container, key []byte) (data []byte, err error) {
	h := hmac.New(sha256.New, key)
	h.Write(signedBlock.Iv)
	h.Write(signedBlock.Length)
	h.Write(signedBlock.Data)
	if !hmac.Equal(h.Sum(nil), signedBlock.Hmac) {
		return nil, errors.New("HMAC mismatch")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	blen := make([]byte, len(signedBlock.Length))
	data = make([]byte, len(signedBlock.Data))

	mode := cipher.NewCBCDecrypter(block, signedBlock.Iv)
	mode.CryptBlocks(blen, signedBlock.Length)
	mode.CryptBlocks(data, signedBlock.Data)
	strlen := strings.Replace(string(blen), "\x00", "", -1)

	originalLength, err := strconv.Atoi(strlen)
	if err != nil {
		return nil, err
	}

	return data[:originalLength], nil
}

// Verify verifies the signed block using the key and returns true if the block is valid
func Verify(signedBlock types.Container, key []byte) (bool, error) {
	if len(signedBlock.Hmac) == 0 {
		return false, errors.New("HMAC missing")
	}

	h := hmac.New(sha256.New, key)
	h.Write(signedBlock.Data)
	return hmac.Equal(h.Sum(nil), signedBlock.Hmac), nil
}

// SerializeContainer serializes the container and returns the encoded data
func SerializeContainer(c types.Container, encf types.EncodingFunc) ([]byte, error) {
	var buff bytes.Buffer
	enc := gob.NewEncoder(&buff)
	err := enc.Encode(c)
	if err != nil {
		return nil, err
	}
	return encf(buff.Bytes())
}

// DeserializeContainer deserializes the data and returns the container
func DeserializeContainer(data []byte, encf types.EncodingFunc) (types.Container, error) {

	data, err := encf(data)
	if err != nil {
		return types.Container{}, err
	}
	// ...
	var c types.Container
	buff := bytes.NewBuffer(data)
	dec := gob.NewDecoder(buff)
	err = dec.Decode(&c)
	if err != nil {
		return types.Container{}, err
	}
	return c, nil
}

func signContainer(c types.Container, key []byte) (types.Container, error) {
	h := hmac.New(sha256.New, key)
	h.Write(c.Iv)
	h.Write(c.Length)
	h.Write(c.Data)
	c.Hmac = h.Sum(nil)
	return c, nil
}
