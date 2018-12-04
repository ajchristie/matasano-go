package set2

import (
  "fmt"
  "set1"
  "crypto/rand"
  rd "math/rand"
)


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
    outtext[aes.BlockSize*i:aes.BlockSize*(i+1)] = op(intext[aes.BlockSize*i:])
  }
  return outtext
}

// for challenge 11
func EncryptionOracle(ptext []byte) []byte {
  key := make([]byte, 16)
  _, err := rand.Read(key)
  if err != nil {
    panic("Error:", err)
  }
  f := rd.Intn(5) + 5
  b := rd.Intn(5) + 5
  n : = f + len(ptext) + b
  messed := make([]byte, n)
  for i := 0; i < f; i++ {
    messed[i] = rd.Intn(255)
  }
  for i := f + len(ptext); i < n; i++ {
    messed[i] = rd.Intn(255)
  }
  copy(messed[f:f+len(ptext)], ptext)
  choice := rd.Intn(1)
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
