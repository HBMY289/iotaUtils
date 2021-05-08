package iotaUtils

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha512"
	"encoding/binary"

	//"encoding/hex"

	"github.com/btcsuite/btcutil/bech32"
	"github.com/tyler-smith/go-bip39"
	"golang.org/x/crypto/blake2b"
)

var hmacKeyEd25519 = []byte("ed25519 seed")

func SeedFromMnemonic(mnemonic string) []byte {
	seed := bip39.NewSeed(mnemonic, "")
	return seed
}

func keyWithPath(M []byte, path []uint32) []byte {
	I := M
	for _, i := range path {
		I = childKey(I, i)
	}
	return I
}

func MasterKey(seed []byte) []byte {
	hmac := hmac.New(sha512.New, hmacKeyEd25519)
	_, err := hmac.Write(seed)
	if err != nil {
		panic(err)
	}
	return hmac.Sum(nil)
}
func childKey(parentKey []byte, childIdx uint32) []byte {
	var data []byte
	childIdxBytes := uint32Bytes(hardened(childIdx))
	data = append([]byte{0x0}, parentKey[:32]...)
	data = append(data, childIdxBytes...)
	hmac := hmac.New(sha512.New, parentKey[32:])
	_, err := hmac.Write(data)
	if err != nil {
		panic(err)
	}
	return hmac.Sum(nil)
}

func EdAddress(subSeed []byte) []byte {
	key := ed25519.NewKeyFromSeed(subSeed)
	publicKey := key.Public().(ed25519.PublicKey)
	hash := blake2b.Sum256(publicKey)
	return hash[:]

}

func Bech32FromEd25119(addrBytes []byte) string {
	conv, err := bech32.ConvertBits(append([]byte{0}, addrBytes...), 8, 5, true)
	if err != nil {
		panic(err)
	}
	addr, err := bech32.Encode("atoi", conv)
	if err != nil {
		panic(err)
	}
	return addr
}

func hardened(i uint32) uint32 {
	return i + uint32(0x80000000)
}

func uint32Bytes(i uint32) []byte {
	bytes := make([]byte, 4)
	binary.BigEndian.PutUint32(bytes, i)
	return bytes
}
