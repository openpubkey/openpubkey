package reader

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/openpubkey/openpubkey/ajwks"
	"github.com/stretchr/testify/require"
)

func TestReader(t *testing.T) {
	err := read()
	require.NoError(t, err)
}

func TestRequest(t *testing.T) {

	suiClient := NewSuiJwksArchive("https://fullnode.mainnet.sui.io:443")
	jwksMap, err := suiClient.GetLatestJwks(context.TODO())
	require.NoError(t, err)

	for iss, jwks := range jwksMap {
		println(iss, len(jwks))
	}

	depth := 350
	jwksMapPast, err := suiClient.GetPastJwks(context.TODO(), depth)
	require.NoError(t, err)
	require.NotNil(t, jwksMapPast)

	for iss, jwksList := range jwksMapPast {
		println(iss)
		for _, jwkData := range *jwksList {
			println("\t", jwkData.CreateTime, jwkData.Epoch)
		}
	}

	for iss, jwksList := range jwksMapPast {
		aJwks := ajwks.New(iss)
		for _, save := range *jwksList {

			err = aJwks.AddJwksSave(save)
			if err != nil {
				require.NoError(t, err)
			}
		}
		aJwks.Print()
		j, err := aJwks.GetSaves()
		require.NoError(t, err)
		fmt.Println(string(j))
		err = aJwks.SaveToFile("jwks-" + strings.Split(aJwks.Issuer, ".")[1] + "-" + "350" + ".json")
		require.NoError(t, err)
	}
}

func TestRead(t *testing.T) {
	archive, err := ajwks.NewFromFile("jwks-google-10.json")
	require.NoError(t, err)
	archive.Print()
}
