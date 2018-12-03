package main

import (
  "fmt"
  "ioutil"
  "encoding/hex"
  "encoding/base64"
  "strings"
  "math"
  "sort"
  "crypto/aes"
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
  score := float32(len(filtered)) / len(s)
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

// a type to hold sort scores when detecting and breaking Caesar-enciphered texts
type Result struct {
  fscore float32
  bscore float32
  shift int
  xord string
}

// sort.Interface signature for Result slices
type byScore []Result

func (r byScore) len() int {
  return len(r)
}

func (r byScore) Swap(i, j int) {
  r[i], r[j] = r[j], r[i]
}

func (r byScore) Less(i, j int) bool { // BasicScore is dominant key for sort
  return (r[i].fscore <= r[j].fscore) && (r[i].bscore > r[j].bscore)
}

func BreakCaesar(s string) (int, string) { // s comes in hex encoded...
  decoded := hex.DecodeString(s)
  results := make([]Result, 255)
  var minScore float32 = 1000.0 // only using FrequencyScore here
  best = make(Result)
  for i:= 1; i < 256; i++ {
    shifted := make([]byte, len(decoded))
    score := 0.0
    for j := range decoded {
      shifted[j] = i ^ decoded[j]
    }
    freqScore = FrequencyScore(shifted)
    bScore = BasicScore(shifted)
    result := Result{fscore, bscore, i, shifted}
    results[i-1] = result
    if freqScore < minScore {
      minScore = freqScore
      best = result
    }
  }
return best.shift, string(best.xord)
}

// for challenge 4
func FindCaesar(l []string) Result {
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
  sort.SliceStable(byScore(results))
  return results[0]
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

func FindKeyLength(ct []byte) int {
  var minIndex int = 1000
  var guess int
  for keylength := 2; keylength < 41; keylength++ {
    segs := MakeSegments(ct, keylength)
    var roundMinIndex int = 150
    for i := 0; i < len(segs); i++ {
      for j := i+1; j < len(segs); j++ {
        index := float32(HammingDistance(segs[i], segs[j])) / keylength
        if index == 0.0 {
          continue
        } else if index < roundMinIndex {
          roundMinIndex = index
        }
      }
    }
    if roundMinIndex < minIndex {
      minIndex = roundMinIndex
      guess = keylength
    }
  }
  return guess
}

func BreakVigenere(ct []byte) (string, string) {
  keylength := FindKeyLength(ct)
  numBlocks := len(ct) / keylength
  padLength := (keylength - (len(ct) % keylength)) % keylength
  for i := 0; i < padLength; i++ {
    append(ct, byte(padLength))
  }
  rows := MakeSegments(ct, keylength)
  shifts := make([]byte, keylength)
  for i := 0; i < keylength; i++ {
    column := make([]byte, len(rows))
    for j, row := range rows {
      column[j] = row[i]
    }
    shifts[i], _ := BreakCaesar(hex.EncodeToString(column))
  }
  key := string(shifts)
  decryption := string(Vigenere(ct, key))
  return key, decryption
}

func LoadCT(path string) string {
  dat, err := ioutil.ReadFile(path)
  if err != nil {
    panic(err)
  }
  return string(dat)
}

// for challenge 7
func AES128ECBenc(intext, key, []byte, which string) []byte {
  cipher, err := aes.NewCipher(key)
  if err != nil {
    panic(err)
  }
  if (len(intext) % aes.BlockSize) != 0 {
    panic("Failure: Input not a multiple of BlockSize.")
  }
  var blocks int = len(intext) / aes.BlockSize
  outtext := make([]byte, len(text))
  if which == "e" {
    op : = cipher.Encrypt
  } else if which == "d" {
    op := cipher.Decrypt
  } else {
    panic("Failure: Encrypt/Decrypt mode undetermined. Last argument must be e or d.")
  }
  for i := 0; i < blocks; i++ {
    outtext[aes.BlockSize*i:aes.BlockSize*(i+1)] = op(intext[aes.BlockSize*i:])
  }
  return outtext
}

// for challenge 8
// NB: I wasn't in the mood to implement another results type and keep a ranked list, which is
// obviously the smart move here. But I know from a previous attempt this will work, so TS
func Catch128ECB(ctexts [][]byte) []byte {
  var maxReps int = 0
  var candidate []byte
  for i, ctext := range ctexts {
    segs := MakeSegments(ctext, 16)
    counter := make(map[string]int)
    for j, seg := range segs {
      k := string(seg)
      counter[k] += 1
    }
    for _, value := range counter {
      if value > maxReps {
        maxReps = value
        candidate = ctext
      }
    }
  }
  return candidate
}
