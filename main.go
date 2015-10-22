// Copyright 2013 Coding Robots. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Command memoires-decrypt decrypts journals encrypted with Mémoires 4.0 and later.
package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/subtle"
	"errors"
	"flag"
	"io"
	"log"
	"os"

	"github.com/dchest/blake2b"
	"golang.org/x/crypto/scrypt"
)

var (
	fPassword = flag.String("p", "", "password")
	fInFile   = flag.String("in", "", "encrypted journal file")
	fOutFile  = flag.String("out", "", "decrypted SQLite file")
)

func main() {
	flag.Parse()
	log.SetFlags(0)
	if *fPassword == "" || *fInFile == "" || *fOutFile == "" {
		flag.Usage()
		return
	}
	inf, err := os.Open(*fInFile)
	if err != nil {
		log.Fatal(err)
	}
	defer inf.Close()
	outf, err := os.Create(*fOutFile)
	if err != nil {
		log.Fatal(err)
	}
	defer outf.Close()
	err = Decrypt(inf, outf, []byte(*fPassword))
	if err != nil {
		os.Remove(*fOutFile)
		log.Fatal(err)
	}
}

var (
	ErrWrongFormat        = errors.New("wrong file format")
	ErrUnsupportedVersion = errors.New("unsupported version")
	ErrWrongPassword      = errors.New("wrong password")
	ErrCorrupted          = errors.New("file corrupted")
)

const headerSize = 8 /*id*/ + 1 /*ver*/ + 1 /*logN*/ + 1 /*logR*/ + 1 /*logP*/ + 32 /*salt*/ + 16 /*iv*/ + 32 /*hash*/ + 32 /*header MAC*/

func Decrypt(r io.Reader, w io.Writer, password []byte) error {
	// Read the whole input file into memory.
	var buf bytes.Buffer
	_, err := io.Copy(&buf, r)
	if err != nil {
		return err
	}
	input := buf.Bytes()
	header := input[:headerSize]
	content := input[headerSize : len(input)-32]

	// Check ID string.
	if string(header[:8]) != "MEM_encr" {
		return ErrWrongFormat
	}

	// Check format version.
	if header[8] != 1 {
		return ErrUnsupportedVersion
	}

	// Read KDF parameters.
	logN, logR, logP := header[9], header[10], header[11]
	salt := header[12:44]

	// Read IV for encryption.
	iv := header[44:60]

	// Check header hash.
	curhash := blake2b.Sum256(header[:60])
	if subtle.ConstantTimeCompare(curhash[:], header[60:92]) != 1 {
		return ErrCorrupted
	}

	// Derive keys.
	macKey, encKey, err := deriveKeys(password, salt, logN, logR, logP)
	if err != nil {
		return err
	}

	// Check header MAC.
	h := blake2b.NewMAC(32, macKey)
	h.Write(header[:92])
	if subtle.ConstantTimeCompare(h.Sum(nil), header[92:124]) != 1 {
		return ErrWrongPassword
	}

	// Check content MAC.
	h.Reset()
	h.Write(input[:len(input)-32])
	if subtle.ConstantTimeCompare(h.Sum(nil), input[len(input)-32:]) != 1 {
		return ErrCorrupted
	}

	// Decrypt.
	if len(content)%aes.BlockSize != 0 {
		return ErrCorrupted
	}
	a, err := aes.NewCipher(encKey)
	if err != nil {
		panic(err.Error())
	}
	out := make([]byte, len(content))
	dec := cipher.NewCBCDecrypter(a, iv)
	dec.CryptBlocks(out, content)

	result := 0

	// Check and strip padding.
	n := int(out[len(out)-1])
	result |= subtle.ConstantTimeLessOrEq(n, 0)
	result |= subtle.ConstantTimeLessOrEq(aes.BlockSize+1, n)
	result |= subtle.ConstantTimeLessOrEq(len(out)+1, n)
	// Now that we have established whether n is within bounds (this will
	// influence the final result), make it actually inside bounds.
	n %= aes.BlockSize + 1
	haveLastBlock := out[len(out)-aes.BlockSize:]
	var needLastBlock [aes.BlockSize]byte
	copy(needLastBlock[:], haveLastBlock)
	for i := len(needLastBlock) - n; i < len(needLastBlock); i++ {
		needLastBlock[i] = byte(n)
	}
	result |= subtle.ConstantTimeByteEq(byte(subtle.ConstantTimeCompare(haveLastBlock, needLastBlock[:])), 0)
	if result != 0 {
		return ErrCorrupted
	}
	out = out[:len(out)-n]

	nw, err := w.Write(out)
	if err != nil {
		return err
	}
	if nw != len(out) {
		return io.ErrShortWrite
	}
	return nil
}

func deriveKeys(password, salt []byte, logN, logR, logP uint8) (macKey []byte, encKey []byte, err error) {
	if logN > 32 {
		return nil, nil, errors.New("logN is too large")
	}
	if logR > 6 {
		return nil, nil, errors.New("logR is too large")
	}
	if logP > 6 {
		return nil, nil, errors.New("logP is too large")
	}
	N := int(1 << uint(logN))
	r := int(1 << uint(logR))
	p := int(1 << uint(logP))
	dk, err := scrypt.Key(password, salt, N, r, p, 64)
	if err != nil {
		return nil, nil, err
	}
	macKey = dk[0:32]
	encKey = dk[32:64]
	return
}
