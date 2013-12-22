// Copyright 2013 Coding Robots. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"io/ioutil"
	"testing"
)

func TestDecrypt(t *testing.T) {
	in, err := ioutil.ReadFile("testdata/encrypted.memoire")
	if err != nil {
		t.Fatal(err)
	}
	out, err := ioutil.ReadFile("testdata/decrypted.memoire")
	if err != nil {
		t.Fatal(err)
	}
	var dec bytes.Buffer
	err = Decrypt(bytes.NewReader(in), &dec, []byte("1234"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(dec.Bytes(), out) {
		t.Fatalf("bad decryption")
	}
}
