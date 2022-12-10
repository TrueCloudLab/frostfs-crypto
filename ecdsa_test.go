package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	"crypto/x509"
	"encoding/hex"
	"math/big"
	"strconv"
	"testing"

	"github.com/TrueCloudLab/frostfs-crypto/test"
	"github.com/stretchr/testify/require"
)

var testKeys = [...]string{
	"0375099c302b77664a2508bec1cae47903857b762c62713f190e8d99912ef76737",
	"025188d33a3113ac77fea0c17137e434d704283c234400b9b70bcdf4829094374a",
	"02c4c574d1bbe7efb2feaeed99e6c03924d6d3c9ad76530437d75c07bff3ddcc0f",
	"02563eece0b9035e679d28e2d548072773c43ce44a53cb7f30d3597052210dbb70",
	"02f8152966ad33b3c2622bdd032f5989fbd63a9a3af34e12eefee912c37defc880",
	"0252d9fd2376f6b3bcb4706cad54ec031d95a1a70414129286c247cd2bc521f73f",
	"0251ec65b2496b1d8ece3efe68a8b57ce7bc75b4171f07fa5b26c63a27fb4f9216",
	"025f7d63e18e6b896730f45989b7a8d00c0b86c75c2b834d903bc681833592bdcc",
	"02d351a4c87ec3b33e62610cb3fd197962c0081bbe1b1b888bc41844f4c6df9cd3",
	"036e3859e6ab43c0f45b7891761f0da86a7b62f931f3d963efd3103924920a73b3",
	"03c02a93134f98d9c78ec54b1b1f97fc64cd81360f53a293f41e4ad54aac3c5717",
	"03fea219d4ccfd7641cebbb2439740bb4bd7c4730c1abd6ca1dc44386533816df9",
	"02a33413277a319cc6fd4c54a2feb9032eba668ec587f307e319dc48733087fa61",
}

func TestMarshalUnmarshal(t *testing.T) {
	t.Run("prepared public keys: unmarshal / marshal", func(t *testing.T) {
		for i := range testKeys {
			bytes, err := hex.DecodeString(testKeys[i])
			require.NoErrorf(t, err, testKeys[i])

			key := UnmarshalPublicKey(bytes)
			res := MarshalPublicKey(key)
			require.Equal(t, testKeys[i], hex.EncodeToString(res))
		}
	})

	t.Run("try to use stored keys", func(t *testing.T) {
		for i := 0; i < 10; i++ {
			i := i
			sk := test.DecodeKey(i)

			t.Run("marshal key_"+strconv.Itoa(i), func(t *testing.T) {
				bytes := MarshalPublicKey(&sk.PublicKey)
				require.Equal(t, testKeys[i], hex.EncodeToString(bytes))
			})

			t.Run("unmarshal key_"+strconv.Itoa(i), func(t *testing.T) {
				bytes, err := hex.DecodeString(testKeys[i])
				require.NoError(t, err)

				pk := UnmarshalPublicKey(bytes)
				require.Equal(t, pk, &sk.PublicKey)
			})
		}
	})

	t.Run("prepared private key: unmarshal / marshal", func(t *testing.T) {
		walletPublicKey := "03fb2e07eba5477dd7de3f627d8803eb86bc36b98132f51d81017343bb6585d9c7"
		walletPrivateKey := "dc80f6900b7b7a791496c06aa77695d744fafaaeff5c143801eb97935448c671"

		data, err := hex.DecodeString(walletPrivateKey)
		require.NoError(t, err)

		_, err = x509.ParseECPrivateKey(data)
		require.Error(t, err)

		privateKey, err := UnmarshalPrivateKey(data)
		require.NoError(t, err)

		require.Equal(t, hex.EncodeToString(MarshalPublicKey(&privateKey.PublicKey)), walletPublicKey)
		require.Equal(t, data, MarshalPrivateKey(privateKey))
	})

	t.Run("marshal / unmarshal public key with 31 byte X point", func(t *testing.T) {
		privateKeyString := "4dd8baa41612a74c1cc664102330115f9b3f4d0fc9b7e4f95c4aceb5cbf335d6"

		privateKeyHex, err := hex.DecodeString(privateKeyString)
		require.NoError(t, err)

		privateKey, err := UnmarshalPrivateKey(privateKeyHex)
		require.NoError(t, err)
		require.Len(t, privateKey.PublicKey.X.Bytes(), 31)

		publicKeyHex := MarshalPublicKey(&privateKey.PublicKey)
		require.Len(t, publicKeyHex, PublicKeyCompressedSize)

		publicKey := UnmarshalPublicKey(publicKeyHex)
		require.NotNil(t, publicKey)
		require.Equal(t, *publicKey, privateKey.PublicKey)
	})
}

func TestSignVerify(t *testing.T) {
	t.Run("should not fail when we pass bad data to unmarshalXY", func(t *testing.T) {
		var (
			data = []byte("Hello world")
			key  = test.DecodeKey(0)
		)

		require.NotPanics(t, func() {
			{ // 1. simple example
				UnmarshalPublicKey(nil)
			}

			{ // 2. pass bad data (not public key)
				r1, s1, err := ecdsa.Sign(rand.Reader, key, hashBytes(data))
				require.NoError(t, err)

				sign := marshalXY(key.Curve, r1, s1)
				UnmarshalPublicKey(sign)
			}

			{ // 3. bad big.Ints
				sign := marshalXY(elliptic.P256(), big.NewInt(0), big.NewInt(1))
				UnmarshalPublicKey(sign)
			}
		})
	})

	t.Run("using prepared hash", func(t *testing.T) {
		var (
			data = []byte("Hello world")
			sum  = sha512.Sum512(data)
			key  = test.DecodeKey(0)
		)
		sig, err := SignHash(key, sum[:])
		require.NoError(t, err)
		require.NoError(t, VerifyHash(&key.PublicKey, sum[:], sig))
	})

	t.Run("low level", func(t *testing.T) {
		var (
			data  = []byte("Hello world")
			curve = elliptic.P256()
			key   = test.DecodeKey(0)
		)

		r1, s1, err := ecdsa.Sign(rand.Reader, key,
			hashBytes(data))
		require.NoError(t, err)

		sign := marshalXY(key.Curve, r1, s1)

		{ // This is just to validate, that we are on right way.. try to unmarshal R/S from sign
			// validate bytes length
			byteLen := (curve.Params().BitSize + 7) >> 3
			require.Len(t, sign, 1+2*byteLen)

			// uncompressed form?
			require.Equal(t, byte(4), sign[0])

			// validate R / S
			p := curve.Params().P
			r := new(big.Int).SetBytes(sign[1 : 1+byteLen])
			s := new(big.Int).SetBytes(sign[1+byteLen:])
			require.True(t, r.Cmp(p) < 0)
			require.True(t, s.Cmp(p) < 0)

			// don't check curves
			// require.True(t, curve.IsOnCurve(r, s))
		}

		r2, s2 := unmarshalXY(sign)
		require.NotNil(t, r2)
		require.NotNil(t, s2)

		require.Equal(t, r1.Bytes(), r2.Bytes())
		require.Equal(t, s2.Bytes(), s2.Bytes())
	})

	t.Run("high level", func(t *testing.T) {
		var (
			data = []byte("Hello world")
			key  = test.DecodeKey(0)
		)

		sign, err := Sign(key, data)
		require.NoError(t, err)

		for i := 0; i < 100; i++ {
			require.NoError(t, Verify(&key.PublicKey, data, sign))
		}
	})
}
