package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	//"strings"

	//"github.com/consensys/gnark-crypto/signature"
)

func main(){
	//The GenerateKey method takes in a reader that returns random bits, and the number of bits
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err !=nil {
		panic(err)
	}
	// public key is part of the *rsa.PrivateKey struct
	publicKey := privateKey.PublicKey

	// Use the public and private keys
	// https://play.golang.org/p/tldFUt2c4nx
	modulusBytes := base64.StdEncoding.EncodeToString(privateKey.N.Bytes())
	privateExponentBytes := base64.StdEncoding.EncodeToString(privateKey.N.Bytes())
	fmt.Printf("\nModulusBytes: %x\n", modulusBytes)
	fmt.Printf("\nPrivateExponetBytes: %x\n", privateExponentBytes)
	fmt.Printf("\nPublicKey: %x\n\n", publicKey.E)

	encryptedBytes, err := rsa.EncryptOAEP(
		sha256.New(),
		rand.Reader,
		&publicKey,

		[]byte("Super secret message"),
		nil)
	if err !=nil {
			panic(err)
	}
	fmt.Print("Encrypted bytes: \n", encryptedBytes)

// The first argument is an optional random data generator (the rand.Reader we used before)
// we can set this value as nil 
// The OEAPOptions in the end signify that we encrypted the data using OEAP, and that we used 
// SHA256 5o hash the input.
decryptedBytes, err := privateKey.Decrypt(nil, encryptedBytes, &rsa.OAEPOptions{Hash: crypto.SHA256})
if err !=nil {
	panic(err)
}
// We get back the original information in the form of bytes, which we cast to a string and fmt.Println
fmt.Println("\nDecrypted message: ", string(decryptedBytes))

msg := []byte("Verifiable message")
// Before signing, we need to hash our message
// the hash is waht we acctually sign
msgHash := sha256.New()
_, err = msgHash.Write(msg)
if err !=nil {
	panic(err)
}

msgHashSum := msgHash.Sum(nil)

// in order to generate the signature, we provide a random number generator,
// our private key, the hashing algorithm that we used, and the hash sum
// of our message
signature, err := rsa.SignPSS(rand.Reader, privateKey, crypto.SHA256, msgHashSum, nil)
if err !=nil {
	panic(err)
}

// to verify the signature, we provide the public key, the hashing algorithm
// the hash sum of our message and the signature we generated previiously 
// there is an optional "options" parameter which can omit for now // nil 
err = rsa.VerifyPSS(&publicKey, crypto.SHA256, msgHashSum, signature, nil)
if err !=nil {
	fmt.Println("could not verify signatrue: ", err)
	return
}
// If we don't get amy errors form the 'VerifyPSS' method, that means our 
// signature is valid
fmt.Println("Signature verified")

	}


// Excellent RSA in a nutshell tutoral + ex. code
// https://www.sohamkamani.com/golang/rsa-encryption/
