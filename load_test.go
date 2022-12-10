package crypto

import (
	"crypto/x509"
	"encoding/hex"
	"io/ioutil"
	"os"
	"testing"

	"github.com/TrueCloudLab/frostfs-crypto/test"
	"github.com/stretchr/testify/require"
)

func Test_LoadPrivateKey_FromWIF(t *testing.T) {
	for i := 0; i < 10; i++ {
		expected := test.DecodeKey(i)

		wif, err := WIFEncode(expected)
		require.NoError(t, err)

		actual, err := LoadPrivateKey(wif)
		require.NoError(t, err)

		require.Equal(t, expected, actual)
	}
}

func Test_LoadPrivateKey_FromHexString(t *testing.T) {
	for i := 0; i < 10; i++ {
		expected := test.DecodeKey(i)

		hs := hex.EncodeToString(expected.D.Bytes())

		actual, err := LoadPrivateKey(hs)
		require.NoError(t, err)

		require.Equal(t, expected, actual)
	}
}

func Test_LoadPrivateKey_FromFile(t *testing.T) {
	for i := 0; i < 10; i++ {
		expected := test.DecodeKey(i)

		file, err := ioutil.TempFile("", "_marshaled.key")
		require.NoError(t, err)

		defer func() {
			require.NoError(t, file.Close())
			require.NoError(t, os.Remove(file.Name()))
		}()

		data, err := x509.MarshalECPrivateKey(expected)
		require.NoError(t, err)

		_, err = file.Write(data)
		require.NoError(t, err)

		actual, err := LoadPrivateKey(file.Name())
		require.NoError(t, err)

		require.Equal(t, expected, actual)
	}
}

func Test_LoadPrivateKey_FromCompressedFormatFile(t *testing.T) {
	for i := 0; i < 10; i++ {
		expected := test.DecodeKey(i)

		file, err := ioutil.TempFile("", "_compressed.key")
		require.NoError(t, err)

		defer func() {
			require.NoError(t, file.Close())
			require.NoError(t, os.Remove(file.Name()))
		}()

		_, err = file.Write(expected.D.Bytes())
		require.NoError(t, err)

		actual, err := LoadPrivateKey(file.Name())
		require.NoError(t, err)

		require.Equal(t, expected, actual)
	}
}
