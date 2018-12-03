package set2

import (
  "fmt"
  "set1"
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
func AES128CBC(intext, key []byte) []byte {
  
}
