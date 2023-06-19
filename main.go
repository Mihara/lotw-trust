package main

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"embed"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"math"
	"os"
	"reflect"
	"time"

	"github.com/blang/semver/v4"
	"github.com/fxamacker/cbor/v2"
	"github.com/integrii/flaggy"
	"software.sslmate.com/src/go-pkcs12"
)

//go:embed version.txt
var version string

const minSupportedVersion = "0.0.3"

const sigHeader = "\nLOTW-TRUST SIG\n"
const footerSize = 2 // uint16 to keep the size of the sig block.

var signCmd *flaggy.Subcommand
var verifyCmd *flaggy.Subcommand
var l *log.Logger

var keyFile string
var keyPass string
var dumpDer bool
var inputFile string
var outputFile string
var sigFile string

// SigBlock is a struct containing the signature and associated data.
// This structure is meant to be stable from here on out, but currently isn't.
// It is encoded in the file in a standard CBOR packet, see https://cbor.io/
type SigBlock struct {
	Version     string    `cbor:"0,keyasint"`
	Callsign    string    `cbor:"1,keyasint"`
	Signature   []byte    `cbor:"2,keyasint,omitempty"`
	SigningTime time.Time `cbor:"3,keyasint,omitempty"`
	Certificate []byte    `cbor:"4,keyasint,omitempty"`
	CA          [][]byte  `cbor:"5,keyasint,omitempty"`
}

//go:embed roots/*.der
var dataFiles embed.FS

func init() {

	l = log.New(os.Stderr, "", 1)
	l.SetFlags(0)

	keyPass = ""

	flaggy.SetName("lotw-trust")
	flaggy.SetDescription(fmt.Sprint("Sign and verify arbitrary files with your LoTW tQSL signing key. \nversion ", version))

	flaggy.DefaultParser.AdditionalHelpAppend = `
Copyright © 2023 Eugene Medvedev (R2AZE).
See the source code at: https://github.com/Mihara/lotw-trust
Released under the terms of MIT license.`

	// Create the subcommand
	signCmd = flaggy.NewSubcommand("sign")
	signCmd.Description = "Sign a file with your LoTW key."
	signCmd.AddPositionalValue(&keyFile, "CALLSIGN.p12", 1, true, "Your LoTW signing key.")
	signCmd.String(&keyPass, "p", "password", "Password for unlocking the key, if required.")
	signCmd.String(&sigFile, "s", "sig_file", "Save the signature block into a separate file. You can use '=' to send it to standard output.")
	signCmd.AddPositionalValue(&inputFile, "INPUT", 2, true, "Input file to be signed. '=' to read from standard input.")
	signCmd.AddPositionalValue(&outputFile, "OUTPUT", 3, false, "Output file. '=' to write to standard output.")

	verifyCmd = flaggy.NewSubcommand("verify")
	verifyCmd.Description = "Verify a file signed with a LoTW key."
	verifyCmd.Bool(&dumpDer, "d", "dump_der", "Dump included CA certificates for investigation.")
	verifyCmd.String(&sigFile, "s", "sig_file", "Read the signature block from a separate file. You can use '=' to read it from standard input.")
	verifyCmd.AddPositionalValue(&inputFile, "INPUT", 1, true, "Input file to be verified. '=' to read from standard input.")
	verifyCmd.AddPositionalValue(&outputFile, "OUTPUT", 2, false, "Output file. '=' to write to standard output.")

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

func check(e error, message string) {
	if e != nil {
		l.Fatal(message, e)
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

func slurpFile(filename string) []byte {
	var fileData []byte
	var err error
	if inputFile == "=" {
		fileData, err = io.ReadAll(os.Stdin)
	} else {
		fileData, err = os.ReadFile(filename)
	}
	check(err, "Error while reading input file:")
	return fileData
}

func saveFile(filename string, fileData []byte) {
	if filename != "" {
		if filename == "=" {
			if _, err := os.Stdout.Write(fileData); err != nil {
				l.Fatal("Error while saving a file:", err)
			}
		} else {
			if err := os.WriteFile(filename, fileData, 0666); err != nil {
				l.Fatal("Error while saving a file:", err)
			}
		}
	}
}

func main() {

	myVersion, _ := semver.Parse(version)

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
		// Signing a file
		keyData, err := os.ReadFile(keyFile)
		check(err, "Could not read the key file:")

		pKey, cert, caChain, err := pkcs12.DecodeChain(keyData, keyPass)
		check(err, "Could not make sense of the key file:")

		if time.Now().After(cert.NotAfter) {
			l.Fatal("Cannot use a LoTW certificate beyond its expiry time.")
		}
		if time.Now().Before(cert.NotBefore) {
			l.Fatal("Cannot use a LoTW certificate before it goes active.")
		}

		callsign := getCallsign(*cert)
		if callsign == "" {
			l.Fatal("The signing key does not appear to be a LoTW key.")
		}

		// Slurp the input file...
		fileData := slurpFile(inputFile)

		signingTime := time.Now().UTC().Truncate(time.Second)

		var hashingData []byte
		dateString, _ := signingTime.MarshalText()

		hashingData = append(fileData, dateString...)

		hashed := sha256.Sum256(hashingData)
		signature, err := rsa.SignPKCS1v15(nil,
			pKey.(*rsa.PrivateKey),
			crypto.SHA256,
			hashed[:],
		)
		check(err, "Signing failure, which probably means a new type of LoTW key:")

		// Now we need to filter roots out of the chain.
		// This is also pretty cringe, golang people, how do you live like that.
		var certlist [][]byte
		for _, c := range caChain {
			if !certInList(rootCerts, c) {
				certlist = append(certlist, c.Raw)
			}
		}

		// And there we have it, our signature data.
		sig := SigBlock{
			Version:     version,
			Callsign:    callsign,
			Signature:   signature,
			Certificate: cert.Raw,
			CA:          certlist,
			SigningTime: signingTime,
		}

		// Now we're back to trying to stuff them into a sig block.
		buf, err := cbor.Marshal(sig)
		check(err, "Could not assemble a sig block, something is very weird.")

		sigBlock := append([]byte(sigHeader), buf...)

		// If the sig block somehow got longer than 65kb, we have a problem anyway.
		if len(sigBlock) > math.MaxUint16 {
			l.Fatal("Signature block too long, which means something else went wrong.")
		}

		sigLen := uint16(len(sigBlock))
		lb := new(bytes.Buffer)
		_ = binary.Write(lb, binary.BigEndian, sigLen)

		sigBlock = append(sigBlock, lb.Bytes()...)

		// Save it.
		saveFile(outputFile, append(fileData, sigBlock...))
		// Notice this will only try saving anything if sigFile is given.
		saveFile(sigFile, sigBlock)

	} else if verifyCmd.Used {
		// Verifying a file.

		// Now I get to do it backwards!
		var err error
		fileData := slurpFile(inputFile)

		var sigBlock []byte

		if sigFile == "" {
			// The last two bytes of the file are the size of the sig block.
			lb := fileData[len(fileData)-footerSize:]
			lbBuf := new(bytes.Buffer)
			_, _ = lbBuf.Write(lb)
			var sigLen uint16
			err = binary.Read(lbBuf, binary.BigEndian, &sigLen)
			check(err, "Could not read signature block tail.")

			split := len(fileData) - footerSize - int(sigLen)

			if split < 0 {
				l.Fatal("Broken or missing signature block.")
			}

			sigBlock = fileData[split:]
			fileData = fileData[:split]

		} else {
			sigBlock = slurpFile(sigFile)
		}

		if !reflect.DeepEqual(sigBlock[:len(sigHeader)], []byte(sigHeader)) {
			l.Fatal("Missing signature header, file probably isn't signed.")
		}

		// Now we need to unmarshal the sig.
		var sigData SigBlock
		err = cbor.Unmarshal(sigBlock[len(sigHeader):], &sigData)
		check(err, "Could not parse signature block:")

		// We can verify the signatures on versions lower than ours, sometimes, but not vice versa.
		sigVersion, err := semver.Parse(sigData.Version)
		check(err, "Broken version number in signature block:")

		if myVersion.Compare(sigVersion) < 0 {
			l.Fatal("File is signed with a newer version of lotw-trust than v{}", myVersion)
		}

		if myVersion.Compare(sigVersion) > 0 {
			oldVersion, _ := semver.Parse(minSupportedVersion)
			if sigVersion.Compare(oldVersion) < 0 {
				l.Fatal("Cannot verify signatures made with versions older than v{}", minSupportedVersion)
			}
		}

		cert, err := x509.ParseCertificate(sigData.Certificate)
		check(err, "Could not parse the public key included with signature:")

		// Build the pool of intermediary certs supplied with the sig.
		extraCerts := x509.NewCertPool()
		for idx, der := range sigData.CA {
			crt, err := x509.ParseCertificate(der)
			check(err, "Could not parse intermediate certificate authority data:")
			extraCerts.AddCert(crt)
			if dumpDer {
				// Save certificates: This is the easy way to send me a LoTW certificate
				// lotw-trust does not yet recognize.
				if err := os.WriteFile(
					fmt.Sprintf("%s_%d.der", sigData.Callsign, idx),
					crt.Raw, 0666); err != nil {
					l.Fatal(err)
				}
			}
		}

		// Verify the actual signature.
		var hashingData []byte
		verificationTime := sigData.SigningTime.UTC().Truncate(time.Second)
		dateString, err := verificationTime.MarshalText()
		check(err, "Broken time information in signature:")
		hashingData = append(fileData, dateString...)

		hashed := sha256.Sum256(hashingData)
		err = rsa.VerifyPKCS1v15(
			cert.PublicKey.(*rsa.PublicKey),
			crypto.SHA256,
			hashed[:],
			sigData.Signature,
		)
		check(err, "Failed to verify signature:")

		_, err = cert.Verify(x509.VerifyOptions{
			Intermediates: extraCerts,
			Roots:         roots,
			CurrentTime:   verificationTime,
			KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		})
		check(err, "Failed to verify public key:")

		displayTime, _ := verificationTime.UTC().MarshalText()
		l.Println("Signed by:", getCallsign(*cert), "on", string(displayTime))

		saveFile(outputFile, fileData)

		// Everything went fine!
		os.Exit(0)

	} else {
		flaggy.ShowHelp("")
	}

}
