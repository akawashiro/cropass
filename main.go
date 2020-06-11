package main

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

// BlockCipher represents block cipher.
type BlockCipher interface {
	Encrypt(plain []byte) ([]byte, error)
	Decrypt(encrypted []byte) ([]byte, error)
}

// AesCbcPkcs7Cipher encrypts with AES/CBC/PKCS7.
type AesCbcPkcs7Cipher struct {
	initialVector []byte
	block         cipher.Block
}

// NewAesCbcPkcs7Cipher make new AesCbcPkcs7Cipher.
func NewAesCbcPkcs7Cipher(key, iv []byte) (*AesCbcPkcs7Cipher, error) {
	keyLen := len(key)
	if (keyLen != 16) && (keyLen != 24) && (keyLen != 32) {
		return nil, errors.New("illegal key length. key length for AES must be 128, 192, 256 bit")
	}
	if len(iv) != aes.BlockSize {
		return nil, errors.New("illegal initial vector size")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, errors.New(err.Error() + " failed to create AES cipher block")
	}
	return &AesCbcPkcs7Cipher{
		initialVector: iv,
		block:         block,
	}, nil
}

// pad function make padding according to RFC 5652 6.3. Content-encryption Process  (PKCS#7 Padding)
func (c *AesCbcPkcs7Cipher) pad(b []byte) []byte {
	padSize := aes.BlockSize - (len(b) % aes.BlockSize)
	pad := bytes.Repeat([]byte{byte(padSize)}, padSize)
	return append(b, pad...)
}

// unpad function delete padding according to PKCS#7 Padding
func (c *AesCbcPkcs7Cipher) unpad(b []byte) []byte {
	padSize := int(b[len(b)-1])
	return b[:len(b)-padSize]
}

// Encrypt plain with AES/CBC/PKCS#7.
func (c *AesCbcPkcs7Cipher) Encrypt(plain []byte) ([]byte, error) {
	encrypter := cipher.NewCBCEncrypter(c.block, c.initialVector)
	padded := c.pad(plain)
	encrypted := make([]byte, len(padded))
	encrypter.CryptBlocks(encrypted, padded)
	return encrypted, nil
}

// Decrypt plain with AES/CBC/PKCS#7.
func (c *AesCbcPkcs7Cipher) Decrypt(encrypted []byte) ([]byte, error) {
	mode := cipher.NewCBCDecrypter(c.block, c.initialVector)

	plain := make([]byte, len(encrypted))
	mode.CryptBlocks(plain, encrypted)
	return c.unpad(plain), nil
}

// KeyLength the length of key which is used for padding
const KeyLength = 32

var cropassPassDir = ""
var cropassPassFile = ""

func encryptPassFile(pass []byte, contents string) {
	iv := make([]byte, aes.BlockSize)
	if _, err := rand.Read(iv); err != nil {
		log.Fatal(err)
	}
	c, err := NewAesCbcPkcs7Cipher(pass, iv)
	if err != nil {
		fmt.Println(err)
		os.Exit(0)
	}
	en, err := c.Encrypt([]byte(contents))
	en = append(en, iv...)

	_, err = os.Stat(cropassPassFile)
	if !os.IsNotExist(err) {
		now := time.Now().Unix()
		n := strconv.FormatInt(now, 10)
		os.Rename(cropassPassFile, filepath.Join(cropassPassDir, "cropass-secret-"+n))
	}
	ioutil.WriteFile(cropassPassFile, en, 644)
}

func decryptPassFile(pass []byte) string {
	_, err := os.Stat(cropassPassFile)
	if os.IsNotExist(err) {
		return ""
	}

	en, err := ioutil.ReadFile(cropassPassFile)
	if err != nil {
		fmt.Println(err)
		os.Exit(0)
	}
	c, err := NewAesCbcPkcs7Cipher(pass, en[len(en)-aes.BlockSize:])
	de, err := c.Decrypt(en[:len(en)-aes.BlockSize])
	if err != nil {
		fmt.Println(err)
		os.Exit(0)
	}
	return string(de)
}

func getMasterPass() ([]byte, error) {
	stdin := bufio.NewScanner(os.Stdin)
	fmt.Print("master password: ")
	stdin.Scan()
	s := []byte(stdin.Text())

	if len(s) >= KeyLength {
		return s, nil
	} else {
		padSize := KeyLength - len(s)
		pad := bytes.Repeat([]byte{byte(padSize)}, padSize)
		return append(s, pad...), nil
	}
}

func getMasterPassWithDoubleCheck() ([]byte, error) {
	stdin := bufio.NewScanner(os.Stdin)
	fmt.Print("master password: ")
	stdin.Scan()
	s := stdin.Text()

	fmt.Print("master password again: ")
	stdin.Scan()
	t := stdin.Text()

	if s == t {
		s := ([]byte(s))
		if len(s) >= KeyLength {
			return s, nil
		} else {
			padSize := KeyLength - len(s)
			pad := bytes.Repeat([]byte{byte(padSize)}, padSize)
			return append(s, pad...), nil
		}
	} else {
		return []byte(""), errors.New("Two passwords do not match. ")
	}
}

func showPass(site string) {
	pass, err := getMasterPass()
	if err != nil {
		fmt.Println(err)
		os.Exit(0)
	}
	contents := decryptPassFile(pass)
	fmt.Print(contents)
}

var letters = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")

func randSeq(n int) string {
	b := make([]rune, n)
	for i := range b {
		j, err := rand.Int(rand.Reader, big.NewInt(int64(len(letters))))
		if err != nil {
			panic(err)
		}
		b[i] = letters[j.Int64()]
	}
	return string(b)
}

func newPass(site string, user string) {
	now := strconv.FormatInt(time.Now().Unix(), 10)
	passForSite := randSeq(16)
	newline := site + " " + user + " " + passForSite + " " + now + "\n"

	pass, err := getMasterPassWithDoubleCheck()
	if err != nil {
		fmt.Println(err)
		os.Exit(0)
	}
	contents := decryptPassFile(pass) + newline
	encryptPassFile(pass, contents)
	fmt.Print(newline)
}

func addPass(site string, user string, passForSite string) {
	now := strconv.FormatInt(time.Now().Unix(), 10)
	newline := site + " " + user + " " + passForSite + " " + now + "\n"

	pass, err := getMasterPassWithDoubleCheck()
	if err != nil {
		fmt.Println(err)
		os.Exit(0)
	}
	contents := decryptPassFile(pass) + newline
	encryptPassFile(pass, contents)
	fmt.Print(newline)
}

func importPass() {
	fmt.Print("Plain text password file: ")
	stdin := bufio.NewScanner(os.Stdin)
	stdin.Scan()
	filename := stdin.Text()
	importContents, err := ioutil.ReadFile(filename)
	if err != nil {
		panic(err)
	}
	pass, err := getMasterPassWithDoubleCheck()
	if err != nil {
		fmt.Println(err)
		os.Exit(0)
	}
	contents := decryptPassFile(pass)
	encryptPassFile(pass, contents+string(importContents))
}

func main() {
	cropassPassDir = os.Getenv("CROPASS_PASS_DIR")
	cropassPassFile = filepath.Join(cropassPassDir, "cropass-secret")
	if cropassPassDir == "" {
		fmt.Println("CROPASS_PASS_DIR is not setted.")
		os.Exit(0)
	}
	fmt.Println(cropassPassFile)
	if len(os.Args) < 2 {
		fmt.Println("The length of input is too short.")
		os.Exit(0)
	}
	command := os.Args[1]
	if command == "show" {
		site := ""
		if 3 <= len(os.Args) {
			site = os.Args[2]
		}
		showPass(site)
	} else if command == "new" {
		if 4 <= len(os.Args) {
			site := os.Args[2]
			user := os.Args[3]
			newPass(site, user)
		} else {
			fmt.Println("The length of input is too short for new.")
			os.Exit(0)
		}
	} else if command == "add" {
		if 5 <= len(os.Args) {
			site := os.Args[2]
			user := os.Args[3]
			pass := os.Args[4]
			addPass(site, user, pass)
		} else {
			fmt.Println("The length of input is too short for add.")
			os.Exit(0)
		}
	}
}
