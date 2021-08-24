package bls

import (
	"fmt"
	"github.com/wxnacy/wgo/arrays"
	"github.com/biu"
	"io/ioutil"
	"strings"

	"strconv"
	"bytes"
	"crypto/rand"
	"crypto/sha256"

	"golang.org-x-text/unicode/norm"
	"golang.org/x/crypto/pbkdf2"
	cbg "github.com/chia-bls-go"
	"crypto/sha512"
)

func GenerateEntropy() ([]byte, error) {
	entropy := make([]byte, 32)
	_, err := rand.Read(entropy)
	fmt.Println("entropy",entropy)
	if err != nil {
		return nil, fmt.Errorf("failed to generate entropy: %v", err)
	}
	return entropy, nil
}

func getEntropyBits(entropy []byte) (string, error){
	if 32 == len(entropy) {
		CS := len(entropy) / 4 	//CS：8

		entropyHash := sha256.Sum256(entropy)
		entropyHashBits := toBitsString(entropyHash[:])
		ckSumBits := entropyHashBits[:CS]

		var entropyBits bytes.Buffer
		entropyBits.WriteString(toBitsString(entropy))
		entropyBits.WriteString(ckSumBits)
		return entropyBits.String(), nil
	}
	return "", fmt.Errorf("required entropy length: 32 but got: %d", len(entropy))
}

func wordIndex(entropyBits string) ([]string) {
	entropyBits = strings.TrimSpace(entropyBits)
	var sbits []string
	index := 0
	for i := 0; i < len(entropyBits)/11; i++ {
		sbits = append(sbits, entropyBits[index:index+11])
		index += 11
	}
	return sbits
}

func wordsFromIndex(index []string, wordList []string) ([]string, error) {
	var words []string
	for _, idx := range index {
		id, err := strconv.ParseInt(idx, 2, 16)
		if err != nil {
			return nil, fmt.Errorf("failed to parse int: %v", err)
		}
		words = append(words, wordList[id])
	}

	return words, nil
}

func GenerateMnemonic() ([]string, error) {
	entropy, err := GenerateEntropy()
	if err != nil {
		return nil, err
	}

	entropyBits, err := getEntropyBits(entropy)
	if err != nil {
		return nil, err
	}

	if len(entropyBits) % 11 != 0 {
		return nil, fmt.Errorf("EntropyBits have a length mismatch")
	}

	index := wordIndex(entropyBits)

	wordList, err := loadWords("english.txt")
	if err != nil {
		return nil, fmt.Errorf("can't load bip_39_word")
	}
	mnemonic, err := wordsFromIndex(index, wordList) 
	if err != nil {
		return nil, err
	}
	return mnemonic, nil
}

func CheckMnemonic(mnemonic []string) (bool) {
	if len(mnemonic) == 24 || (arrays.ContainsString(mnemonic, "") < 0) || len(mnemonic) % 3 == 0 { 
		//load bip39_words_list
		wordList, err := loadWords("english.txt")
		if err != nil {
			return false
		}
		//get words index
		var wordsIndex []int 
		for _, word := range mnemonic{
			index := arrays.ContainsString(wordList, word) 
			if index < 0 {
		 		fmt.Println(word, "is not in the mnemonic dictionary; may be misspelled")
				return false
			}
			wordsIndex = append(wordsIndex, index)
		}
		//toBitString
		var entropyBits bytes.Buffer
		for _, index := range wordsIndex {
			entropyBits.WriteString(fmt.Sprintf("%011b", index))	
		}

		CS := len(mnemonic) / 3			//8
		ENT := len(mnemonic) * 11 - CS	//264-8=256

		if (len(mnemonic) * 11 == len(entropyBits.String()) && ENT % 32 == 0) {
			entropyBytes := biu.BinaryStringToBytes(entropyBits.String()[:ENT])
			entropyBytesHash := sha256.Sum256(entropyBytes)
			entropyBytesHashBit := toBitsString(entropyBytesHash[:])
			checkSum := entropyBytesHashBit[:CS]

			checksum_bytes := entropyBits.String()[ENT:]

			if checkSum == checksum_bytes {
				fmt.Println("check succuse!")
				return true
			}
		}
	}
	return false
}

func loadWords(path string) (wordsList []string, err error) {
	fileContent, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("Failed to read file: " + path)
	}
	wordsList = strings.Split(string(fileContent), "\n")

	if len(wordsList) != 2048 {
		return nil, fmt.Errorf("require 2048 words but got %d", len(wordsList))
	}
	return wordsList, err
}

func toBitsString(data []byte) string {
	var buf bytes.Buffer
	for _, b := range data {
		buf.WriteString(fmt.Sprintf("%.8b", b))
	}

	return buf.String()
}

func Mnemonic_to_key(mnemonic string) ([]byte){
	salt_str := "mnemonic" + ""

	salt := norm.NFKD.String(salt_str)
	mnemonic_normalized := norm.NFKD.String(mnemonic)

	seed := pbkdf2.Key([]byte(mnemonic_normalized), []byte(salt), 2048, 64, sha512.New)

	pr_key := cbg.KeyGen(seed)
	return pr_key.Bytes()
}