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
	"os"
	"strconv"
	"time"
)

// BlockCipher はブロック暗号を表現する
type BlockCipher interface {
	Encrypt(plain []byte) ([]byte, error)
	Decrypt(encrypted []byte) ([]byte, error)
}

// AesCbcPkcs7Cipher はAES/CBC/PKCS7 のブロック暗号を表現する
type AesCbcPkcs7Cipher struct {
	// 初期ベクトル
	initialVector []byte
	// ブロック暗号
	block cipher.Block
}

// NewAesCbcPkcs7Cipher は AES/CBC/PKCS#7 のブロック暗号を作成し、返却する
func NewAesCbcPkcs7Cipher(key, iv []byte) (*AesCbcPkcs7Cipher, error) {
	// 鍵長チェック
	keyLen := len(key)
	if (keyLen != 16) && (keyLen != 24) && (keyLen != 32) {
		return nil, errors.New("illegal key length. key length for AES must be 128, 192, 256 bit")
	}
	// 初期ベクトル長チェック
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

// pad は RFC 5652 6.3. Content-encryption Process に記述された通りに
// b にパディングとしてのバイトを追加する (PKCS#7 Padding)
func (c *AesCbcPkcs7Cipher) pad(b []byte) []byte {
	padSize := aes.BlockSize - (len(b) % aes.BlockSize)
	pad := bytes.Repeat([]byte{byte(padSize)}, padSize)
	return append(b, pad...)
}

// unpad は PKCS#7 Padding に従って付与されたパディングを削除する
func (c *AesCbcPkcs7Cipher) unpad(b []byte) []byte {
	padSize := int(b[len(b)-1])
	return b[:len(b)-padSize]
}

// Encrypt は plain を AES/CBC/PKCS#7 で暗号化する。
func (c *AesCbcPkcs7Cipher) Encrypt(plain []byte) ([]byte, error) {
	encrypter := cipher.NewCBCEncrypter(c.block, c.initialVector)

	// PKCS#7 に沿ってパディングを付与
	padded := c.pad(plain)
	// 暗号化
	encrypted := make([]byte, len(padded))
	encrypter.CryptBlocks(encrypted, padded)
	return encrypted, nil
}

// Decrypt は encrypted を AES/CBC/PKCS#7 で復号化する
func (c *AesCbcPkcs7Cipher) Decrypt(encrypted []byte) ([]byte, error) {
	mode := cipher.NewCBCDecrypter(c.block, c.initialVector)

	plain := make([]byte, len(encrypted))
	mode.CryptBlocks(plain, encrypted)
	// パディングを除去
	return c.unpad(plain), nil
}

// KeyLength the length of key which is used for padding
const KeyLength = 32

var cropassPassDir = ""

func getMasterPass() ([]byte, error) {
	stdin := bufio.NewScanner(os.Stdin)
	fmt.Println("master password: ")
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

func show(site string) {
	passFiles, err := ioutil.ReadDir(cropassPassDir)
	if err != nil {
		panic(err)
	}
	for _, file := range passFiles {
		fmt.Println(file.Name())
	}
}

func new(site string, user string) {
}

func add(site string, user string, pass string) {
	now := time.Now().Unix()
	n := strconv.FormatInt(now, 10)
	p, err := getMasterPassWithDoubleCheck()
	if err != nil {
		fmt.Println(err)
		os.Exit(0)
	}
	iv := make([]byte, aes.BlockSize)
	if _, err := rand.Read(iv); err != nil {
		log.Fatal(err)
	}
	c, err := NewAesCbcPkcs7Cipher(p, iv)
	if err != nil {
		fmt.Println(err)
		os.Exit(0)
	}
	en, err := c.Encrypt([]byte(site + " " + user + " " + pass + " " + n))
	if err != nil {
		fmt.Println(err)
		os.Exit(0)
	}
	en = append(en, iv...)

	c, err = NewAesCbcPkcs7Cipher(p, en[len(en)-aes.BlockSize:])
	de, err := c.Decrypt(en[:len(en)-aes.BlockSize])
	if err != nil {
		fmt.Println(err)
		os.Exit(0)
	}
	fmt.Println(string(de))
}

func importPass() {
}

func main() {
	cropassPassDir = os.Getenv("CROPASS_PASS_DIR")
	if cropassPassDir == "" {
		fmt.Println("CROPASS_PASS_DIR is not setted.")
		os.Exit(0)
	}
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
		show(site)
	} else if command == "new" {
		if 4 <= len(os.Args) {
			site := os.Args[2]
			user := os.Args[3]
			new(site, user)
		} else {
			fmt.Println("The length of input is too short for new.")
			os.Exit(0)
		}
	} else if command == "add" {
		if 5 <= len(os.Args) {
			site := os.Args[2]
			user := os.Args[3]
			pass := os.Args[4]
			add(site, user, pass)
		} else {
			fmt.Println("The length of input is too short for add.")
			os.Exit(0)
		}
	}
}
