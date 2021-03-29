package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"flag"
	"fmt"
	"io"
	"os"
)

var inputFilename string
var keyFilename string
var outputFilename string
var isGenKey bool
var isEncryptionOptional bool
var isDecrypt bool

var aesKeySizeBytes = 32

func removePadding(buf *[]byte, blockSize int) {
	i := len(*buf) - blockSize - 1
	for i > 0 {
		if (*buf)[i] == uint8(0x80) {
			break
		}
		i--
	}
	*buf = (*buf)[:i]
}

func padPlainText(buffer *[]byte, blockSize int) {
	paddingLength := blockSize - (len(*buffer) % blockSize)
	tempBuffer := make([]byte, paddingLength+blockSize)

	tempBuffer[0] = uint8(0x80)
	for i := 1; i < len(tempBuffer); i++ {
		tempBuffer[i] = uint8(0)
	}
	*buffer = append(*buffer, tempBuffer...)
}

func readKeyFile(buffer []byte, filename string) (int, error) {
	file, err := os.Open(filename)
	if err != nil {
		fmt.Println(err)
		return 0, err
	}

	n, err := file.Read(buffer)
	if err != nil {
		fmt.Println(err)
		return 0, err
	}

	return n, nil
}

func readContentFile(filename string) ([]byte, error) {
	file, err := os.Open(filename)
	if err != nil {
		fmt.Println(err)
		return nil, err
	}

	buffer := make([]byte, 8)
	fileText := make([]byte, 0, 20)
	for {
		n, err := file.Read(buffer)
		if err == io.EOF {
			break
		} else {
			fileText = append(fileText, buffer[:n]...)
		}
	}
	return fileText, nil
}

func writeOutputFile(buffer []byte, filename string) (int, error) {
	file, err := os.Create(filename)
	if err != nil {
		fmt.Println(err)
		return 0, err
	}

	return file.Write(buffer)
}

func genRandom(buffer []byte) error {
	if _, err := rand.Reader.Read(buffer); err != nil {
		return err
	}
	return nil
}

func init() {
	flag.StringVar(&inputFilename, "in", "", "input file")
	flag.StringVar(&outputFilename, "out", "", "output file")
	flag.StringVar(&keyFilename, "kfile", "", "path of keyfile")
	flag.BoolVar(&isGenKey, "genkey", false, "if set, encryptor will generate a new key, if the -kfile flag is also used, the key will be written to the provided file")
	flag.BoolVar(&isDecrypt, "decrypt", false, "if set, encryptor will decrypt input, default setting is encryption")

	flag.Parse()
}

func main() {
	// Check if a new key is to be generated
	// If not, read keyfile into key
	if flag.NFlag() == 0 {
		flag.PrintDefaults()
		return
	}
	if keyFilename == "" {
		fmt.Println("you must provide a -kfile argument")
		return
	}
	key := make([]byte, aesKeySizeBytes)
	if isGenKey {
		key = make([]byte, aesKeySizeBytes)
		if err := genRandom(key); err != nil {
			fmt.Println(err)
			return
		}
		writeOutputFile(key, keyFilename)
	} else {
		_, err := readKeyFile(key, keyFilename)
		if err != nil {
			fmt.Println(err)
			return
		}
	}

	cipherBlock, err := aes.NewCipher(key)
	if err != nil {
		fmt.Println(err)
		return
	}
	var output []byte
	var input []byte

	if inputFilename == "" {
		buffer := bytes.NewBuffer(make([]byte, 0, 256))
		stat, _ := os.Stdin.Stat()
		size := stat.Size()
		if size <= 0 {
			fmt.Println("input must not be empty, use parameter flag '-in' or send input via stdin")
			return
		}
		io.Copy(buffer, os.Stdin)
		input = buffer.Bytes()
	} else {
		input, _ = readContentFile(inputFilename)
	}

	if isDecrypt {
		output = make([]byte, len(input)-cipherBlock.BlockSize())

		iv := input[:cipherBlock.BlockSize()]
		input = input[cipherBlock.BlockSize():]

		blockMode := cipher.NewCBCDecrypter(cipherBlock, iv)

		blockMode.CryptBlocks(output, input)
		removePadding(&output, cipherBlock.BlockSize())
	} else {
		padPlainText(&input, cipherBlock.BlockSize())
		output = make([]byte, len(input)+cipherBlock.BlockSize())

		iv := output[:cipherBlock.BlockSize()]
		rand.Reader.Read(iv)

		blockMode := cipher.NewCBCEncrypter(cipherBlock, iv)

		blockMode.CryptBlocks(output[cipherBlock.BlockSize():], input)
	}

	if outputFilename == "" {
		r := bytes.NewReader(output)
		io.Copy(os.Stdout, r)
	} else {
		writeOutputFile(output, outputFilename)
	}
}
