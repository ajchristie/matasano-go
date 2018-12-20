package set2

import (
  "fmt"
  "encoding/base64"
  "github.com/ajchristie/set1"
  crand "crypto/rand"
  "math/rand"
  "encoding/binary"
)

// set up some easier access to cryptographically secure random integers
// usage: declare var src cSource then use rand.New with this source
// methods are provided for both Source and Source64 types
type cSource struct {}

func (s cSource) Seed(seed int64) {} // no need to seed; we'll pull random from dev

func (s cSource) Uint64() uint64 {
  var v uint64
  err := binary.Read(crand.Reader, binary.BigEndian, &v)
  if err != nil {
    log.Fatal(err)
  }
  return v
}

func (s cSource) Int63() int64 {
  return int64(s.Uint64() &^ uint64(1<<63))
}

// a function for secure random bytes
func RandomBytes(n int) ([]byte, error) {
  bytes := make([]byte, n)
  _, err := crand.Read(b)
  if err != nil { // error is simply returned and should be checked after call
    return nil, err
  }
  return b, err
}

// for challenge 9
func PKCS7(b []byte, n int) []byte {
  padded := make([]byte, len(b)+n)
  padded[:len(b)] = b
  for i := len(b); i < len(b)+n; i++ {
    padded[i] = byte(i)
  }
  return padded
}

// for challenge 10
func EncAES128CBC(intext, key []byte) []byte {
  cipher, err := aes.NewCipher(key)
  if err != nil {
    panic(err)
  }
  paddingLength := aes.BlockSize - (len(intext) % aes.BlockSize)
  blocks := MakeSegments(PKCS7(intext, paddingLength))
  IV := make([]byte, 16)
  outtext := make([]byte, len(intext) + paddingLength)
  for i, block := range blocks {
    outtext[i] = cipher.Encrypt(set1.FixedLengthXOR(IV, block))
    IV = outtext[i]
  }
  return outtext
}

func EncAES128ECB(intext, key []byte) []byte {
  cipher, err := aes.NewCipher(key)
  if err != nil {
    panic(err)
  }
  paddingLength := aes.BlockSize - (len(intext) % aes.BlockSize)
  blocks := MakeSegments(PKCS7(intext, paddingLength))
  var numBlocks int = len(intext) / aes.BlockSize
  outtext := make([]byte, len(text))
  for i := 0; i < numBlocks; i++ {
    outtext[aes.BlockSize*i:aes.BlockSize*(i+1)] = cipher.Encrypt(intext[aes.BlockSize*i:])
  }
  return outtext
}

// for challenge 11
func EncryptionOracle(ptext []byte) []byte {
  key := make([]byte, 16)
  _, err := crand.Read(key)
  if err != nil {
    panic("Error:", err)
  }
  var src cSource
  rnd = rand.New(src)
  f := rnd.Intn(6) + 5 // these are always going to be the same w/o seeding?
  b := rnd.Intn(6) + 5
  n : = f + len(ptext) + b
  messed := make([]byte, n)
  for i := 0; i < f; i++ {
    messed[i] = rnd.Intn(255)
  }
  for i := f + len(ptext); i < n; i++ {
    messed[i] = rnd.Intn(255)
  }
  copy(messed[f:f+len(ptext)], ptext)
  choice := rnd.Intn(2)
  if choice == 0 {
    return EncAES128ECB(messed, key)
  } else {
    return EncAES128CBC(messed, key)
  }
}

func OracleDetector() string {
  ptext := make([]byte, 48)
  for i := range ptext {
    ptext[i] = byte(65)
  }
  blocks := MakeSegments(EncryptionOracle(ptext), 16)
  if blocks[1] == blocks[2] {
    return "ECB"
  } else {
    return "CBC"
  }
}

// for challange 12
func ECBOracle(ptext []byte) []byte {
  key, err := RandomBytes(16)
  if err != nil {
    panic(err)
  }
  Tail := base64.DecodeString("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3AIE5vLCBJIGp1c3QgZHJvdmUgYnkK")
  ptext = append(ptext, Tail...)
  return EncAES128ECB(ptext, key)
}

func FindSizes() (blockSize, targetSize int) { // normally you'd pass in the encryption oracles
  startLength := len(ECBOracle([]byte("")))
  ptext := make([]byte, 0)
  ctext := make([]byte, 0)
  for {
    ptext = append(ptext, 255)
    ctext = ECBOracle(ptext)
    if len(ctext) != startLength {
      return len(ctext) - startLength, startLength - len(ptext)
    }
  }
}

func ByteXByteDecrypt() string {
  blockSize := 16
  targetSize := 138
  padLength := (blockSize - (targetSize % blockSize)) % blockSize
  attackIndex := targetSize + padLength - 1 // position for decryption
  leader := make([]byte, targetSize + padLength - 1)
  for i := range leader {
    leader[i] = 255
  }
  targetDecryption := make([]byte, targetSize)
  for j := 1; j <= targetSize; j++ {
    targetBlock := ECBOracle(leader)[attackIndex-blockSize:attackIndex+1]
    for i := 0; i <= 256; i++ {
      scanBlock := ECBOracle(leader + targetProgress + i)[attackIndex-blockSize:attackSize+1]
      if scanBlock == targetBlock {
        targetDecryption[j-1] = i
        break
      }
    }
    leader = leader[:len(leader)-j]
  }
  return string(targetDecryption)
}
