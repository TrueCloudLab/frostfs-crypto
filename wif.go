package crypto

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"fmt"

	"github.com/TrueCloudLab/frostfs-crypto/internal"
	"github.com/mr-tron/base58"
)

const (
	// WIFLength constant length of WIF string.
	WIFLength = 38

	// ErrBadWIF when passed WIF-string could not be decoded from base58.
	ErrBadWIF = internal.Error("bad wif")

	// ErrBadChecksum when passed WIF-string could not be verified
	// by last 4 bytes signature.
	ErrBadChecksum = internal.Error("bad checksum")

	// ErrEmptyPrivateKey when PK passed into WIFEncode method is nil.
	ErrEmptyPrivateKey = internal.Error("empty private key")
)

func wifCheckSum(data []byte) []byte {
	sum := sha256.Sum256(data)
	sum = sha256.Sum256(sum[:])

	return sum[:4]
}

// WIFEncode encodes the given private key into a WIF string.
func WIFEncode(key *ecdsa.PrivateKey) (string, error) {
	if key == nil || key.D == nil {
		return "", ErrEmptyPrivateKey
	}

	data := make([]byte, WIFLength)
	data[0] = 0x80
	data[33] = 0x01
	copy(data[1:33], key.D.Bytes())
	copy(data[34:], wifCheckSum(data[:34]))

	return base58.Encode(data), nil
}

// WIFDecode decoded the given WIF string into a private key.
func WIFDecode(wif string) (*ecdsa.PrivateKey, error) {
	data, err := base58.Decode(wif)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBadWIF, err)
	} else if actual := len(data); actual != WIFLength {
		return nil, fmt.Errorf("%w: expect: %d, actual: %d", ErrBadWIF, WIFLength, actual)
	} else if sum := wifCheckSum(data[:34]); !bytes.Equal(data[34:], sum) {
		return nil, ErrBadChecksum
	}

	return UnmarshalPrivateKey(data[1:33])
}
