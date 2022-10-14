package customkdf

import (
	"crypto/sha512"
	"math/big"
	"strings"
	"unicode"

	"golang.org/x/text/unicode/norm"
)

func KDF512(salt []byte, username string, password string) (x *big.Int) {
	p := []byte(PreparePassword(password))

	u := []byte(PreparePassword(username))

	innerHasher := sha512.New() // #nosec
	if _, err := innerHasher.Write(u); err != nil {
		panic(err)
	}
	if _, err := innerHasher.Write([]byte(":")); err != nil {
		panic(err)
	}
	if _, err := innerHasher.Write(p); err != nil {
		panic(err)
	}

	ih := innerHasher.Sum(nil)

	oHasher := sha512.New() // #nosec
	if _, err := oHasher.Write(salt); err != nil {
		panic(err)
	}
	if _, err := oHasher.Write(ih); err != nil {
		panic(err)
	}

	h := oHasher.Sum(nil)
	x = bigIntFromBytes(h)
	return x
}

func PreparePassword(s string) string {
	var out string
	out = string(norm.NFKD.Bytes([]byte(s)))
	out = strings.TrimLeftFunc(out, unicode.IsSpace)
	out = strings.TrimRightFunc(out, unicode.IsSpace)
	return out
}

func bigIntFromBytes(bytes []byte) *big.Int {
	result := new(big.Int)
	for _, b := range bytes {
		result.Lsh(result, 8)
		result.Add(result, big.NewInt(int64(b)))
	}
	return result
}
