package crypto

import (
	"crypto/ecdsa"
	"encoding/hex"
	"testing"

	"github.com/TrueCloudLab/frostfs-crypto/test"
	"github.com/stretchr/testify/require"
)

type (
	NPPrompt struct {
		Key *ecdsa.PrivateKey
		WIF string
	}

	WIFTestCase struct {
		Error error
		Name  string
		WIF   string
		Key   *ecdsa.PrivateKey
	}
)

func npPromptSKWIF(t *testing.T) *NPPrompt {
	key, err := hex.DecodeString("c428b4a06f166fde9f8afcf918194acdde35aa2612ecf42fe0c94273425ded21")
	require.NoError(t, err)

	sk, err := UnmarshalPrivateKey(key)
	require.NoError(t, err)

	return &NPPrompt{
		Key: sk,
		WIF: "L3o221BojgcCPYgdbXsm6jn7ayTZ72xwREvBHXKknR8VJ3G4WmjB",
	}
}

func TestWIF(t *testing.T) {
	kw := npPromptSKWIF(t)

	t.Run("encoding", func(t *testing.T) {
		cases := []WIFTestCase{
			{
				Name: "success #1",
				Key:  test.DecodeKey(0),
				WIF:  "KyKwsDQhb6ncTw9wfoJqMXUABTsMLi36u7BZBBKo5uzmGFEHHDVu",
			},

			{
				Name: "success #2",
				Key:  test.DecodeKey(1),
				WIF:  "Ky2aXYjbxUoMoLaPhyEw8U37BVD6N1rw7mfbbxDv3ULqM9dta7ZW",
			},

			{
				Name: "success #3",
				Key:  test.DecodeKey(2),
				WIF:  "L5LDzGxboJv2CqWKp7v8UGddAMf834DZvMK7muRgNqXTSTwG8pRJ",
			},

			{
				Name: "np-prompt generated SK/WIF",
				Key:  kw.Key,
				WIF:  kw.WIF,
			},

			{
				Name:  "empty key",
				Error: ErrEmptyPrivateKey,
				Key:   nil,
			},
		}

		for i := range cases {
			current := cases[i]
			t.Run(current.Name, func(t *testing.T) {
				actual, err := WIFEncode(current.Key)
				switch current.Error {
				case nil:
					require.NoError(t, err)
					require.Equal(t, current.WIF, actual)
				default:
					require.ErrorIs(t, err, current.Error)
				}
			})
		}
	})
	t.Run("decoding", func(t *testing.T) {
		cases := []WIFTestCase{
			{
				Name: "success #1",
				Key:  test.DecodeKey(0),
				WIF:  "KyKwsDQhb6ncTw9wfoJqMXUABTsMLi36u7BZBBKo5uzmGFEHHDVu",
			},
			{
				Name: "success #2",
				Key:  test.DecodeKey(1),
				WIF:  "Ky2aXYjbxUoMoLaPhyEw8U37BVD6N1rw7mfbbxDv3ULqM9dta7ZW",
			},
			{
				Name: "success #3",
				Key:  test.DecodeKey(2),
				WIF:  "L5LDzGxboJv2CqWKp7v8UGddAMf834DZvMK7muRgNqXTSTwG8pRJ",
			},
			{
				Name: "np-prompt generated SK/WIF",
				Key:  kw.Key,
				WIF:  kw.WIF,
			},
			{
				Error: ErrBadChecksum,
				Name:  "bad checksum",
				WIF:   "KyKwsDQhb6ncTw9wfoJqMXUABTsMLi36u7BZBBKo5uzmGF7rYxf5",
			},
			{
				Error: ErrBadWIF,
				Name:  "bad wif",
				WIF:   "bad_wif",
			},

			{
				Error: ErrBadWIF,
				Name:  "bad wif length",
				WIF:   "L5LDzGxboJv2CqWKp7v8UGddAMf834DZvMK7muRgNqXTSTueCExxDEADBEAF",
			},
		}

		for i := range cases {
			current := cases[i]
			t.Run(current.Name, func(t *testing.T) {
				actual, err := WIFDecode(current.WIF)
				switch current.Error {
				case nil:
					require.NoError(t, err)
					require.Equal(t, current.Key, actual)
				default:
					require.ErrorIs(t, err, current.Error)
				}
			})
		}
	})
}
