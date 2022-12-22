package main

import (
	"fmt"
	"ir/sqstool/aws"
	"log"
	"os"

	"github.com/google/tink/go/aead"
	"github.com/google/tink/go/insecurecleartextkeyset"
	"github.com/google/tink/go/keyset"
)

func main() {

	msg := "Default message"
	asskey := "teste-key"

	// Receber via parametro de comando
	argcount := len(os.Args[1:])
	if argcount > 0 {
		msg = (os.Args[1])
	}

	if argcount > 1 {
		asskey = (os.Args[2])
	}

	testTink(msg, asskey)

	aws.MainConsumer()

}

func testTink(msg string, asskey string) {
	// Ver qual modo: 128-bit and 256-bit AES CTR, 128-bit and 256-bit AES GCM, and ChaCha20/Poly1205
	//  key,_ := keyset.NewHandle(aead.AES128CTRHMACSHA256KeyTemplate())
	//  key,_ := keyset.NewHandle(aead.AES128GCMKeyTemplate())
	//  key,_ := keyset.NewHandle(aead.AES256CTRHMACSHA256KeyTemplate())
	//  key,_ := keyset.NewHandle(aead.AES256GCMKeyTemplate())
	//  key,_ := keyset.NewHandle(aead.ChaCha20Poly1305KeyTemplate())
	//  key,_ := keyset.NewHandle(aead.XChaCha20Poly1305KeyTemplate())

	kh, err := keyset.NewHandle(aead.AES128GCMKeyTemplate())

	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(kh.String())

	a, _ := aead.New(kh)

	ct, _ := a.Encrypt([]byte(msg), []byte(asskey))

	pt, _ := a.Decrypt(ct, []byte(asskey))

	fmt.Printf("Message: %s\nAssociated data: %s\n", msg, asskey)

	fmt.Printf("Cipher text: %x\nPain Text: %s\n\n\n", ct, pt)

	expPriv := &keyset.MemReaderWriter{}
	insecurecleartextkeyset.Write(kh, expPriv)
	fmt.Printf("Key: %s\n\n", expPriv)

}
