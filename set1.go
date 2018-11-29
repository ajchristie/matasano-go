package main

import (
  "fmt"
  "encoding/hex"
  "encoding/base64"
  "strings"
  "math"
  "sort"
)

func main() {

}

// for challenge 1
func HexToBase64(s string) string {
  return base64.EncodeToString(hex.DecodeString(s))
}

// for challenge 2
func FixedLengthXOR(a, b []byte) []byte {
  // we assume a and b have equal length and leave error handling for later
  out := make([]byte, len(a))
  for i := range a {
    out[i] = a[i] ^ b[i]
  }
  return out

}

// for challenge 3
func Filter(vs []byte, f func(byte) bool) []byte {
    vsf := make([]byte, 0)
    for _, v := range vs {
        if f(v) {
            vsf = append(vsf, v)
        }
    }
    return vsf
}

func IsASCII(b byte) bool {
  if (65 <= b && b <= 90) || (97 <= b && b <= 122) || (b == 32) {
    return true
  }
  return false
}

func BasicScore(s []byte) float32 {
  filtered := Filter(s, IsASCII)
  score := float32(len(filtered)) / float32(len(s))
  return score
}

func FrequencyScore(s []byte) float32 {
  std := map[string]float32{"a": 8.167, "b": 1.492, "c": 2.782, "d": 4.253, "e": 12.702, "f":
    2.228, "g": 2.015, "h": 6.094, "i": 6.966, "j": 0.153, "k": 0.772, "l": 4.025, "m": 2.406, "n":
    6.749, "o": 7.507, "p": 1.929, "q": 0.095, "r": 5.987, "s": 6.327, "t": 9.056, "u": 2.758, "v": 0.978, "w": 2.36, "x": 0.15, "y": 1.974, "z": 0.074}
  freqs := map[string]int{"a": 0, "b": 0, "c": 0, "d": 0, "e": 0, "f": 0, "g": 0, "h": 0, "i": 0,
    "j": 0, "k": 0, "l": 0, "m": 0, "n": 0, "o": 0, "p": 0, "q": 0, "r": 0, "s": 0, "t": 0, "u": 0,
    "v": 0, "w": 0, "x": 0, "y": 0, "z": 0}
  filtered = Filter(s, IsASCII)
  for _, x := range filtered {
    if x != 32 {
      c := strings.ToLower(string(x))
      freqs[c] += 1
    }
  }
  l := len(s)
  delta := 0
  for key, value := range freqs {
    delta += math.Abs((float32(value) / l) - std[key])
  }
  return delta
}

type Result struct {
  score float32
  shift int
  xord string
}

type Result2 struct {
  fscore float32
  bscore float32
  shift int
  xord string
}

// actually do an interface for sorting results

func Less(r, s Result) bool {
  return r.score < s.score
}

func freqLess(r, s Result2) bool {
  return r.fscore < s.fscore
}

func basicComp(r, s Result2) bool {
  return r.bscore > s.bscore
}

func BreakCaesar(s string) string { // s comes in hex encoded...
  decoded := hex.DecodeString(s)
  results := make([]Result, 255)
  var minScore float32 = 1000.0
  var best Result
  for i:= 1; i < 256; i++ {
    shifted := make([]byte, len(decoded))
    score := 0.0
    for j := range decoded {
      shifted[j] = i ^ decoded[j]
    }
    score = FrequencyScore(shifted)
    result := Result{score, i, shifted}
    results[i-1] = result
    if score < minScore {
      minScore = score
      best = result
    }
  }
return string(best.xord)
}

// for challenge 4
func FindCaesar(l []string) Result2 {
  results := make([]Result2, len(l)*255)
  for k, ctext := range l {
    decoded := hex.DecodeString(ctext)
    for i := 1; i < 256; i++ {
      xord := make([]byte, len(decoded))
      for j, b := range decoded {
        xord[j] = i ^ b
      }
      freqScore := FrequencyScore(xord)
      bScore := BasicScore(xord)
      results[k + i-1] = Result2{freqScore, bScore, i, xord}
    }
  }
  sort.SliceStable(results, freqLess)
  sort.SliceStable(results, basicComp)
  return result[0]
}

// for challenge 5
func Vigenere(ptext []byte, key string) []byte {
  keybytes := []bytes(key)
  keylength := len(keybytes)
  out := make([]bytes, len(ptext))
  for i := range ptext {
    out[i] = ptext[i] ^ keybytes[i % keylength]
  }
  return out
}

// for challenge 6
func HammingDistance(a,b []byte) int { // assuming a and b have the same length
    var count int
    for i := range a {
      xor := a[i] ^ b[i]
      count += strings.Count(fmt.Sprintf("%b", xor), "1")
    }
    return count
}

func MakeSegments(s []bytes, n int) [][]bytes {
  segNumber := len(s) / n
  segments := make([][]bytes, segNumber)
  for i := 0; i < n; i++ {
    segments[i] = s[i:i+n]
  }
  return segments
}
