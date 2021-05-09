package address

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"

	"github.com/btcsuite/btcutil/bech32"
	"github.com/tyler-smith/go-bip39"
	"golang.org/x/crypto/blake2b"
)

var hmacKeyEd25519 = []byte("ed25519 seed")

const purpose = uint32(44)
const coinType = uint32(4218)

func SeedFromMnemonic(mnemonic string, password string) []byte {
	seed := bip39.NewSeed(mnemonic, password)
	return seed
}

func subSeed(masterKey []byte, path []uint32) []byte {
	key := keyWithPath(masterKey, path)
	return key[:32]
}

func getPath(account, addrIndex uint32, change bool) []uint32 {
	path := []uint32{purpose, coinType, account, 0, addrIndex}
	if change {
		path[3] = 1
	}
	return path
}
func keyWithPath(masterKey []byte, path []uint32) []byte {
	I := masterKey
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

func AddressBytes(subSeed []byte) []byte {
	key := ed25519.NewKeyFromSeed(subSeed)

	publicKey := key.Public().(ed25519.PublicKey)
	hash := blake2b.Sum256(publicKey)
	return hash[:]
}

func AddressBech32(addrBytes []byte, hrp string) string {
	conv, err := bech32.ConvertBits(append([]byte{0}, addrBytes...), 8, 5, true)
	if err != nil {
		panic(err)
	}
	addr, err := bech32.Encode(hrp, conv)
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

func GetAddress(masterKey []byte, account, addrIndex uint32, change bool) *Addr {
	a := new(Addr)
	path := getPath(account, addrIndex, change)
	subSeed := keyWithPath(masterKey, path)[:32]
	a.privateKey = ed25519.NewKeyFromSeed(subSeed)
	a.publicKey = a.privateKey.Public().(ed25519.PublicKey)
	hash := blake2b.Sum256(a.publicKey)
	a.addrBytes = hash[:]
	a.change = change
	return a
}

func (a Addr) Bech32(hrp string) string {
	conv, err := bech32.ConvertBits(append([]byte{0}, a.addrBytes...), 8, 5, true)
	if err != nil {
		panic(err)
	}
	addr, err := bech32.Encode(hrp, conv)
	if err != nil {
		panic(err)
	}
	return addr
}

func (a Addr) Hex() string {
	return hex.EncodeToString(a.addrBytes)
}

func (a Addr) Sign(message []byte) []byte {
	sig := ed25519.Sign(a.privateKey, message)
	return sig

}

func (a Addr) Verify(message, signature []byte) bool {
	return ed25519.Verify(a.publicKey, message, signature)
}

func (a Addr) isChange() bool {
	return a.change
}

type Addr struct {
	privateKey ed25519.PrivateKey
	publicKey  ed25519.PublicKey
	addrBytes  []byte
	change     bool
}
