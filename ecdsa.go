package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	"crypto/x509"
	"fmt"
	"math/big"

	"github.com/TrueCloudLab/frostfs-crypto/internal"
)

const (
	// ErrEmptyPublicKey when PK passed to Verify method is nil.
	ErrEmptyPublicKey = internal.Error("empty public key")

	// ErrInvalidSignature when signature passed to Verify method is mismatch.
	ErrInvalidSignature = internal.Error("invalid signature")

	// ErrCannotUnmarshal when signature ([]byte) passed to Verify method has wrong format
	// and cannot be parsed.
	ErrCannotUnmarshal = internal.Error("could not unmarshal signature")

	// PrivateKeyCompressedSize is constant with compressed size of private key (SK).
	// D coordinate stored, recover PK by formula x, y = curve.ScalarBaseMul(d,bytes).
	PrivateKeyCompressedSize = 32

	// PublicKeyCompressedSize is constant with compressed size of public key (PK).
	PublicKeyCompressedSize = 33

	// PublicKeyUncompressedSize is constant with uncompressed size of public key (PK).
	// First byte always should be 0x4 other 64 bytes is X and Y (32 bytes per coordinate).
	// 2 * 32 + 1
	PublicKeyUncompressedSize = 65
)

// P256 is base elliptic curve.
var curve = elliptic.P256()

// marshalXY converts points into the uncompressed form specified in section 4.3.6 of ANSI X9.62.
// It is also used to marshal signature, for backwards compatibility.
func marshalXY(curve elliptic.Curve, x, y *big.Int) []byte {
	params := curve.Params()
	curveOrderByteSize := params.P.BitLen() / 8
	buf := make([]byte, 1+curveOrderByteSize*2)
	// r and s are not on curve at all, leave for backwards compatibility
	buf[0] = 4
	_ = x.FillBytes(buf[1 : 1+curveOrderByteSize])
	_ = y.FillBytes(buf[1+curveOrderByteSize:])

	return buf
}

// unmarshalXY converts a point, serialized by Marshal, into an x, y pair.
// It is an error if the point is not in uncompressed form.
// On error, x,y = nil.
// Unlike the original version of the code, we ignore that x or y not on the curve
// --------------
// It's copy-paste elliptic.Unmarshal(curve, data) stdlib function, without last line
// of code.
// Link - https://golang.org/pkg/crypto/elliptic/#Unmarshal
func unmarshalXY(data []byte) (x *big.Int, y *big.Int) {
	if len(data) != PublicKeyUncompressedSize {
		return
	} else if data[0] != 4 { // uncompressed form
		return
	}

	p := curve.Params().P
	x = new(big.Int).SetBytes(data[1:PublicKeyCompressedSize])
	y = new(big.Int).SetBytes(data[PublicKeyCompressedSize:])

	if x.Cmp(p) >= 0 || y.Cmp(p) >= 0 {
		x, y = nil, nil
	}

	return
}

// MarshalPublicKey to bytes.
func MarshalPublicKey(key *ecdsa.PublicKey) []byte {
	if key == nil || key.X == nil || key.Y == nil {
		return nil
	}

	return elliptic.MarshalCompressed(curve, key.X, key.Y)
}

// UnmarshalPublicKey from bytes.
func UnmarshalPublicKey(data []byte) *ecdsa.PublicKey {
	if x, y := decodePoint(data); x != nil && y != nil {
		return &ecdsa.PublicKey{
			Curve: curve,
			X:     x,
			Y:     y,
		}
	}

	return nil
}

func decodePoint(data []byte) (x *big.Int, y *big.Int) {
	// empty data
	if len(data) == 0 {
		return
	}

	// tries to unmarshal compressed form
	// returns (nil, nil) when:
	// - wrong len(data)
	// - data[0] != 2 && data[0] != 3
	if x, y = elliptic.UnmarshalCompressed(curve, data); x != nil && y != nil {
		return x, y
	}

	// tries to unmarshal uncompressed form and check that points on curve
	if x, y = unmarshalXY(data); x == nil || y == nil || !curve.IsOnCurve(x, y) {
		x, y = nil, nil
	}

	return x, y
}

// UnmarshalPrivateKey from bytes.
// It is similar to `ecdsa.Generate()` but uses pre-defined big.Int and
// curve for NEO Blockchain (elliptic.P256)
// Link - https://golang.org/pkg/crypto/ecdsa/#GenerateKey
func UnmarshalPrivateKey(data []byte) (*ecdsa.PrivateKey, error) {
	if len(data) == PrivateKeyCompressedSize { // todo: consider using only NEO blockchain private keys
		d := new(big.Int).SetBytes(data)
		priv := new(ecdsa.PrivateKey)
		priv.PublicKey.Curve = curve
		priv.D = d
		priv.PublicKey.X, priv.PublicKey.Y = curve.ScalarBaseMult(data)

		return priv, nil
	}

	return x509.ParseECPrivateKey(data)
}

// MarshalPrivateKey to bytes.
func MarshalPrivateKey(key *ecdsa.PrivateKey) []byte {
	return key.D.Bytes()
}

// hashBytes returns the sha512 sum.
func hashBytes(data []byte) []byte {
	buf := sha512.Sum512(data)
	return buf[:]
}

// Verify verifies the signature of msg using the public key pub. It returns
// nil only if signature is valid.
func Verify(pub *ecdsa.PublicKey, msg, sig []byte) error {
	return VerifyHash(pub, hashBytes(msg), sig)
}

// VerifyHash verifies the signature of msg using it's hash the public key pub.
// It returns nil only if signature is valid.
func VerifyHash(pub *ecdsa.PublicKey, msgHash, sig []byte) error {
	if pub == nil {
		return ErrEmptyPublicKey
	} else if r, s := unmarshalXY(sig); r == nil || s == nil {
		return ErrCannotUnmarshal
	} else if !ecdsa.Verify(pub, msgHash, r, s) {
		return fmt.Errorf("%w: %0x : %0x", ErrInvalidSignature, r, s)
	}

	return nil
}

// Sign signs a message using the private key. If the sha512 hash of msg
// is longer than the bit-length of the private key's curve order, the hash
// will be truncated to that length. It returns the signature as slice bytes.
// The security of the private key depends on the entropy of rand.
func Sign(key *ecdsa.PrivateKey, msg []byte) ([]byte, error) {
	return SignHash(key, hashBytes(msg))
}

// SignHash signs message using it's hash and private key.
func SignHash(key *ecdsa.PrivateKey, msgHash []byte) ([]byte, error) {
	x, y, err := ecdsa.Sign(rand.Reader, key, msgHash)
	if err != nil {
		return nil, err
	}

	return marshalXY(key.Curve, x, y), nil
}
