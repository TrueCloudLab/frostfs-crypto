package crypto

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"fmt"
	"math/big"

	"github.com/TrueCloudLab/frostfs-crypto/internal"
	"github.com/TrueCloudLab/rfc6979"
)

const (
	// RFC6979SignatureSize contains r and s coordinates (32 bytes)
	RFC6979SignatureSize = 64

	// ErrWrongHashSize when passed signature to VerifyRFC6979 has wrong size.
	ErrWrongHashSize = internal.Error("wrong hash size")

	// ErrWrongSignature when passed signature to VerifyRFC6979 isn't valid.
	ErrWrongSignature = internal.Error("wrong signature")
)

// hashBytesRFC6979 returns the sha256 sum.
func hashBytesRFC6979(data []byte) []byte {
	sign := sha256.Sum256(data)
	return sign[:]
}

// SignRFC6979 signs an arbitrary length hash (which should be the result of
// hashing a larger message) using the private key. It returns the
// signature as a pair of integers.
//
// Note that FIPS 186-3 section 4.6 specifies that the hash should be truncated
// to the byte-length of the subgroup. This function does not perform that.
func SignRFC6979(key *ecdsa.PrivateKey, msg []byte) ([]byte, error) {
	return SignRFC6979Hash(key, hashBytesRFC6979(msg))
}

// SignRFC6979Hash signs sha256 hash of the message using the private key.
func SignRFC6979Hash(key *ecdsa.PrivateKey, msgHash []byte) ([]byte, error) {
	if key == nil {
		return nil, ErrEmptyPrivateKey
	}

	r, s := rfc6979.SignECDSA(key, msgHash, sha256.New)
	rBytes, sBytes := r.Bytes(), s.Bytes()
	signature := make([]byte, RFC6979SignatureSize)

	// if `r` has less than 32 bytes, add leading zeros
	ind := RFC6979SignatureSize/2 - len(rBytes)
	copy(signature[ind:], rBytes)

	// if `s` has less than 32 bytes, add leading zeros
	ind = RFC6979SignatureSize - len(sBytes)
	copy(signature[ind:], sBytes)

	return signature, nil
}

func decodeSignature(sig []byte) (*big.Int, *big.Int, error) {
	if ln := len(sig); ln != RFC6979SignatureSize {
		return nil, nil, fmt.Errorf("%w: actual=%d, expect=%d",
			ErrWrongHashSize, ln, RFC6979SignatureSize)
	}

	return new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:]), nil
}

// VerifyRFC6979 verifies the signature of msg using the public key. It
// return nil only if signature is valid.
func VerifyRFC6979(key *ecdsa.PublicKey, msg, sig []byte) error {
	if key == nil {
		return ErrEmptyPublicKey
	} else if r, s, err := decodeSignature(sig); err != nil {
		return err
	} else if !ecdsa.Verify(key, hashBytesRFC6979(msg), r, s) {
		return ErrWrongSignature
	}

	return nil
}

// VerifyRFC6979 verifies the signature of msg using the public key. It
// return nil only if signature is valid.
func VerifyRFC6979Hash(key *ecdsa.PublicKey, msgHash, sig []byte) error {
	if key == nil {
		return ErrEmptyPublicKey
	} else if r, s, err := decodeSignature(sig); err != nil {
		return err
	} else if !ecdsa.Verify(key, msgHash, r, s) {
		return ErrWrongSignature
	}

	return nil
}
