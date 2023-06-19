package main

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"embed"
	"encoding/binary"
	"log"
	"os"
	"reflect"

	"github.com/fxamacker/cbor/v2"
	"github.com/integrii/flaggy"
	"software.sslmate.com/src/go-pkcs12"
)

//go:embed version.txt
var version string

const sigHeader = "\nLOTW-TRUST SIG\n"

var signCmd *flaggy.Subcommand
var verifyCmd *flaggy.Subcommand

var keyFile string
var keyPass string
var inputFile string
var outputFile string

// SigBlock is a struct containing the signature and associated data.
type SigBlock struct {
	Sig []byte   `cbor:"0,keyasint"`
	Cer []byte   `cbor:"1,keyasint"`
	Ca  [][]byte `cbor:"2,keyasint,omitempty"`
}

//go:embed roots/*.der
var dataFiles embed.FS

func init() {

	keyPass = ""

	flaggy.SetName("lotw-trust")
	flaggy.SetDescription("Sign and verify arbitrary files with your LoTW tQSL signing key.")

	// Create the subcommand
	signCmd = flaggy.NewSubcommand("sign")
	signCmd.Description = "Sign a file."
	signCmd.AddPositionalValue(&keyFile, "CALLSIGN.p12", 1, true, "Your LoTW signing key.")
	signCmd.String(&keyPass, "p", "password", "Password for unlocking the key, if required.")
	signCmd.AddPositionalValue(&inputFile, "INPUT", 2, true, "Input file to be signed.")
	signCmd.AddPositionalValue(&outputFile, "OUTPUT", 3, false, "Output file.")

	verifyCmd = flaggy.NewSubcommand("verify")
	verifyCmd.Description = "Verify a file."
	verifyCmd.AddPositionalValue(&inputFile, "INPUT", 1, true, "Input file to be verified.")
	verifyCmd.AddPositionalValue(&outputFile, "OUTPUT", 2, false, "Output file.")

	flaggy.AttachSubcommand(signCmd, 1)
	flaggy.AttachSubcommand(verifyCmd, 1)

	flaggy.SetVersion(version)
	flaggy.Parse()

}

func certInList(a []*x509.Certificate, x *x509.Certificate) bool {
	for _, n := range a {
		// I'm not sure this is the best way to identify if two certs are the same,
		// but should do for now.
		if reflect.DeepEqual(x.SubjectKeyId, n.SubjectKeyId) {
			return true
		}
	}
	return false
}

func check(e error) {
	if e != nil {
		panic(e)
	}
}

func getCallsign(c x509.Certificate) string {
	// This is how LoTW certificates encode callsign, I have no idea why.
	callsign := ""
	for _, subject := range c.Subject.Names {
		if subject.Type.String() == "1.3.6.1.4.1.12348.1.1" {
			callsign = subject.Value.(string)
		}
	}
	return callsign
}

func main() {

	l := log.New(os.Stderr, "", 1)
	l.SetFlags(0)

	// Parse our embedded root certificates.
	// Because x509 stupidly does not export more data about certpool structure,
	// I have to duplicate it.

	roots := x509.NewCertPool()
	var rootCerts []*x509.Certificate

	rootFiles, _ := dataFiles.ReadDir("roots")
	for _, f := range rootFiles {
		der, _ := dataFiles.ReadFile("roots/" + f.Name())
		crt, _ := x509.ParseCertificate(der)
		roots.AddCert(crt)
		rootCerts = append(rootCerts, crt)
	}

	if signCmd.Used {

		// Now for actual code...
		keyData, err := os.ReadFile(keyFile)
		check(err)
		// Empty password for now
		pKey, cert, caChain, err := pkcs12.DecodeChain(keyData, keyPass)
		check(err)

		// Yes, the callsign really has this type.
		callsign := getCallsign(*cert)
		if callsign == "" {
			l.Fatal("The signing key does not appear to be a LoTW key.")
			return
		}

		// Slurp the input file...
		fileData, err := os.ReadFile(inputFile)
		check(err)

		hashed := sha256.Sum256(fileData)

		signature, err := rsa.SignPKCS1v15(nil, pKey.(*rsa.PrivateKey), crypto.SHA256, hashed[:])
		if err != nil {
			l.Fatal("Signing failure, which probably means a new type of LoTW key:", err)
			return
		}

		// Now we need to filter roots out of the chain.
		// This is also pretty cringe, golang people, how do you live like that.
		var certlist [][]byte
		for _, c := range caChain {
			if !certInList(rootCerts, c) {
				certlist = append(certlist, c.Raw)
			}
		}

		// And there we have it, our signature data.
		sig := SigBlock{signature, cert.Raw, certlist}

		// Now we're back to trying to stuff them into a sig block.
		buf, err := cbor.Marshal(sig)
		check(err)

		// TODO: Set up base64 sigs around here, if I'm doing this at all.

		sigBlock := append([]byte(sigHeader), buf...)
		// If the sig block somehow got longer than 65kb, we have a problem anyway.
		sigLen := uint16(len(sigBlock))

		lb := new(bytes.Buffer)
		err = binary.Write(lb, binary.BigEndian, sigLen)
		check(err)

		sigBlock = append(sigBlock, lb.Bytes()...)

		// Save it.
		if err := os.WriteFile(outputFile, append(fileData, sigBlock...), 0666); err != nil {
			l.Fatal(err)
		}

	} else if verifyCmd.Used {

		// Now I get to do it backwards!

		fileData, err := os.ReadFile(inputFile)
		check(err)

		// The last two bytes of the file are the size of the sig block.
		lb := fileData[len(fileData)-2:]
		lbBuf := new(bytes.Buffer)
		_, _ = lbBuf.Write(lb)
		var sigLen uint16
		err = binary.Read(lbBuf, binary.BigEndian, &sigLen)
		check(err)

		split := len(fileData) - 2 - int(sigLen)
		sigBlock := fileData[split:]
		fileData = fileData[:split]

		if !reflect.DeepEqual(sigBlock[:len(sigHeader)], []byte(sigHeader)) {
			l.Fatal("File does not appear to be signed.")
		}
		hashed := sha256.Sum256(fileData)

		// Now we need to unmarshal the sig.
		var sigData SigBlock
		err = cbor.Unmarshal(sigBlock[len(sigHeader):], &sigData)
		check(err)
		cert, err := x509.ParseCertificate(sigData.Cer)
		check(err)

		// Build the pool of intermediary certs supplied with it.
		extraCerts := x509.NewCertPool()
		for _, der := range sigData.Ca {
			crt, _ := x509.ParseCertificate(der)
			extraCerts.AddCert(crt)
		}

		// Verify the actual signature.
		err = rsa.VerifyPKCS1v15(cert.PublicKey.(*rsa.PublicKey), crypto.SHA256, hashed[:], sigData.Sig)
		check(err)

		_, err = cert.Verify(x509.VerifyOptions{
			Intermediates: extraCerts,
			Roots:         roots,
			KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		})
		check(err)
		l.Println("Signed by:", getCallsign(*cert))
		os.Exit(0)

	} else {
		flaggy.ShowHelp("")
	}

}
