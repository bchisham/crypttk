package blocks

import (
	"crypto/hmac"
	"crypto/sha256"
	"github.com/bchisham/crypttk/blocks/types"
	"reflect"
	"testing"
)

const (
	testKey = "dontuserandomkey"
)

func mustgobEncode(data types.Container) []byte {
	d, _ := SerializeContainer(data, NoEncoding)
	return d
}

func mustHexEncode(data types.Container) []byte {
	d, _ := SerializeContainer(data, HexEncoding)
	return d
}

func mustBase64Encode(data types.Container) []byte {
	d, _ := SerializeContainer(data, Base64Encoding)
	return d
}

func musthmac(data []byte, key []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}

func mustEncrypt(data []byte, key []byte) types.Container {
	c, _ := Encrypt(data, key)
	return c
}

func mustDecrypt(data types.Container, key []byte) []byte {
	d, _ := Decrypt(data, key)
	return d
}

func TestDeserializeContainer(t *testing.T) {

	type args struct {
		data []byte
		encf types.EncodingFunc
	}
	tests := []struct {
		name    string
		args    args
		want    types.Container
		wantErr bool
	}{
		{
			name: "Empty Container",
			args: args{
				data: mustgobEncode(types.Container{}),
				encf: NoEncoding,
			},
			want: types.Container{},
		},
		{
			name: "Container with Data",
			args: args{
				data: mustgobEncode(types.Container{Data: []byte{1, 2, 3, 4}}),
				encf: NoEncoding,
			},
			want: types.Container{Data: []byte{1, 2, 3, 4}},
		},
		{
			name: "Container hex encoded",
			args: args{
				data: mustHexEncode(types.Container{Data: []byte{1, 2, 3, 4}}),
				encf: HexDecoding,
			},
			want: types.Container{Data: []byte{1, 2, 3, 4}},
		},
		{
			name: "Container base64 encoded",
			args: args{
				data: mustBase64Encode(types.Container{Data: []byte{1, 2, 3, 4}}),
				encf: Base64Decoding,
			},
			want: types.Container{Data: []byte{1, 2, 3, 4}},
		},
		{
			name: "Invalid Data",
			args: args{
				data: []byte{1, 2, 3, 4},
				encf: NoEncoding,
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := DeserializeContainer(tt.args.data, tt.args.encf)
			if (err != nil) != tt.wantErr {
				t.Errorf("DeserializeContainer() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("DeserializeContainer() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestVerify(t *testing.T) {
	type args struct {
		signedBlock types.Container
		key         []byte
	}
	tests := []struct {
		name    string
		args    args
		want    bool
		wantErr bool
	}{
		{
			name: "Empty Container",
			args: args{
				signedBlock: types.Container{},
				key:         []byte(testKey),
			},
			want:    false,
			wantErr: true,
		},
		{
			name: "Missing HMAC",
			args: args{
				signedBlock: types.Container{Data: []byte{1, 2, 3, 4}},
				key:         []byte(testKey),
			},
			want:    false,
			wantErr: true,
		},
		{
			name: "Valid HMAC",
			args: args{
				signedBlock: types.Container{Data: []byte{1, 2, 3, 4}, Hmac: musthmac([]byte{1, 2, 3, 4}, []byte(testKey))},
				key:         []byte(testKey),
			},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Verify(tt.args.signedBlock, tt.args.key)
			if (err != nil) != tt.wantErr {
				t.Errorf("Verify() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("Verify() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDecrypt(t *testing.T) {
	type args struct {
		encryptedBlock types.Container
		key            []byte
	}
	tests := []struct {
		name    string
		args    args
		want    []byte
		wantErr bool
	}{
		{
			name: "Empty Container",
			args: args{
				encryptedBlock: types.Container{},
				key:            []byte(testKey),
			},
			wantErr: true,
		},
		{
			name: "Missing IV",
			args: args{
				encryptedBlock: types.Container{Data: []byte{1, 2, 3, 4}, Hmac: musthmac([]byte{1, 2, 3, 4}, []byte(testKey))},
				key:            []byte(testKey),
			},
			wantErr: true,
		},
		{
			name: "Valid IV - Length Less than block size",
			args: args{
				encryptedBlock: mustEncrypt([]byte{1, 2, 3, 4}, []byte(testKey)),
				key:            []byte(testKey),
			},
			want: []byte{1, 2, 3, 4},
		},
		{
			name: "Valid IV - Length Greater than block size but not multiple of block size",
			args: args{
				encryptedBlock: mustEncrypt([]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}, []byte(testKey)),
				key:            []byte(testKey),
			},
			want: []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10},
		},
		{
			name: "Valid IV - Length Greater than block size and multiple of block size",
			args: args{
				encryptedBlock: mustEncrypt([]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}, []byte(testKey)),
				key:            []byte(testKey),
			},
			want: []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12},
		},
		{
			name: "Invalid HMAC",
			args: args{
				encryptedBlock: mustEncrypt([]byte{1, 2, 3, 4}, []byte(testKey)),
				key:            []byte("invalidkey"),
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Decrypt(tt.args.encryptedBlock, tt.args.key)
			if (err != nil) != tt.wantErr {
				t.Errorf("Decrypt() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Decrypt() got = %v, want %v", got, tt.want)
			}
		})
	}
}
