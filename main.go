package main

import (
	"bytes"
	"compress/zlib"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"embed"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/adrg/xdg"
	"github.com/blang/semver/v4"
	"github.com/fxamacker/cbor/v2"
	"github.com/integrii/flaggy"
	"software.sslmate.com/src/go-pkcs12"
)

//go:embed version.txt
var version string

const minSupportedVersion = "0.0.3"

const footerSize = 2 // uint16 to keep the size of the sig block.

const textModeHeader = "-----BEGIN LOTW-TRUST MESSAGE-----\n"
const textModeFooter = "\n-----END LOTW-TRUST MESSAGE-----\n"
const textModeSigPem = "LOTW-TRUST SIG"

// Binary mode header is the same with extra newlines.
const sigHeader = "\n" + textModeSigPem + "\n"

var signCmd *flaggy.Subcommand
var verifyCmd *flaggy.Subcommand
var l *log.Logger

var keyFile string
var keyPass string
var dumpDer bool
var omitCert bool
var textMode bool
var inputFile string
var outputFile string
var sigFile string

var dataDir string

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

	dataDir = filepath.Join(xdg.DataHome, "lotw-trust")
	if _, err := os.Stat(dataDir); os.IsNotExist(err) {
		err := os.MkdirAll(dataDir, os.ModeDir|0o755)
		check(err, "Could not create or open "+dataDir)
	}

	keyPass = ""

	flaggy.SetName("lotw-trust")
	flaggy.SetDescription(fmt.Sprint("Sign and verify arbitrary files with your LoTW tQSL signing key. \nversion ", version))

	flaggy.DefaultParser.AdditionalHelpAppend = fmt.Sprintf(`
Public keys are cached in %s

Copyright © 2023 Eugene Medvedev (R2AZE).
See the source code at: https://github.com/Mihara/lotw-trust
Released under the terms of MIT license.`, dataDir)

	// Create the subcommand
	signCmd = flaggy.NewSubcommand("sign")
	signCmd.Description = "Sign a file with your LoTW key."
	signCmd.AddPositionalValue(&keyFile, "CALLSIGN.p12", 1, true, "Your LoTW signing key.")
	signCmd.String(&keyPass, "p", "password", "Password for unlocking the key, if required.")
	signCmd.String(&sigFile, "s", "sig_file", "Save the signature block into a separate file. You can use '=' to send it to standard output.")
	signCmd.Bool(&textMode, "t", "textmode", "Treat the file as readable text and produce a human-readable signature.")
	signCmd.Bool(&omitCert, "a", "abbreviate", "Save a shorter version of signature block that does not include public keys.")
	signCmd.AddPositionalValue(&inputFile, "INPUT", 2, true, "Input file to be signed. '=' to read from standard input.")
	signCmd.AddPositionalValue(&outputFile, "OUTPUT", 3, false, "Output file. '=' to write to standard output.")

	verifyCmd = flaggy.NewSubcommand("verify")
	verifyCmd.Description = "Verify a file signed with a LoTW key."
	verifyCmd.Bool(&textMode, "t", "textmode", "The input contains a text mode signature, and must be treated as such.")
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
		if bytes.Equal(x.SubjectKeyId, n.SubjectKeyId) {
			return true
		}
	}
	return false
}

func check(e error, message string) {
	if e != nil {
		l.Fatal(message, " ", e)
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

func normalizeLineEndings(text []byte) []byte {
	output := normalizeLineEndingsString(string(text))
	return []byte(output)
}

func normalizeLineEndingsString(text string) string {
	// I.e. CRLF, as PGP and friends do.
	// Since we do not actually change the output format,
	// it doesn't matter that much, as long as it's consistent
	// so that a CRLF message does not get mis-verified on an LF system.
	const replacement = "\r\n"

	var replacer = strings.NewReplacer(
		"\r\n", replacement,
		"\r", replacement,
		"\n", replacement,
		"\v", replacement,
		"\f", replacement,
		"\u0085", replacement,
		"\u2028", replacement,
		"\u2029", replacement,
	)
	return replacer.Replace(text)
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

		if textMode {
			// In text mode, we must normalize line endings to something before hashing.
			hashingData = normalizeLineEndings(fileData)
			hashingData = append(hashingData, dateString...)
		} else {
			hashingData = append(fileData, dateString...)
		}

		hashed := sha256.Sum256(hashingData)
		signature, err := rsa.SignPKCS1v15(nil,
			pKey.(*rsa.PrivateKey),
			crypto.SHA256,
			hashed[:],
		)
		check(err, "Signing failure, which probably means you have a new, unknown type of LoTW key:")

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
			SigningTime: signingTime,
		}
		if !omitCert {
			sig.Certificate = cert.Raw
			sig.CA = certlist
		}

		// Now we're back to trying to stuff them into a sig block.
		buf, err := cbor.Marshal(sig)
		check(err, "Could not assemble a sig block, something is very weird.")

		sigBlock := append([]byte(sigHeader), buf...)

		// If the sig block somehow got longer than 65kb, we have a problem anyway.
		if len(sigBlock) > math.MaxUint16 {
			l.Fatal("Signature block too long, which means something else went wrong.")
		}

		var savingData []byte

		if textMode {
			// Text mode makes things vastly more cumbersome.
			// PEM to the rescue!

			textData := textModeHeader
			textData += string(fileData)
			textData += textModeFooter
			savingData = []byte(textData)

			// The actual sig block is gzipped to save space lost from encoding to base64.
			var gzSig bytes.Buffer
			z, _ := zlib.NewWriterLevel(&gzSig, zlib.BestCompression)
			_, _ = z.Write(buf)
			_ = z.Close()

			displayTime, _ := sig.SigningTime.UTC().Truncate(time.Second).MarshalText()
			sigPemBlock := &pem.Block{
				Type:  textModeSigPem,
				Bytes: gzSig.Bytes(),
				Headers: map[string]string{
					"Signer": sig.Callsign,
					"Date":   string(displayTime),
				},
			}

			savingData = append(savingData, pem.EncodeToMemory(sigPemBlock)...)

		} else {
			sigLen := uint16(len(sigBlock))
			lb := new(bytes.Buffer)
			_ = binary.Write(lb, binary.BigEndian, sigLen)

			sigBlock = append(sigBlock, lb.Bytes()...)
			savingData = append(fileData, sigBlock...)
		}

		// Save it.
		saveFile(outputFile, savingData)
		// Notice this will only try saving anything if sigFile is given.
		saveFile(sigFile, sigBlock)

	} else if verifyCmd.Used {
		// Verifying a file.

		// Now I get to do it backwards!
		var err error
		fileData := slurpFile(inputFile)

		var sigBlock []byte

		if sigFile == "" {

			if textMode {
				// Text mode makes everything more complicated on read, too.
				textData := string(fileData)
				_, restText, found := strings.Cut(textData, textModeHeader)
				if !found {
					l.Fatal("The file does not appear to be signed in text mode.")
				}
				signedText, _, found := strings.Cut(restText, textModeFooter)
				if !found {
					l.Fatal("Signed message seems to have lost a chunk.")
				}
				fileData = []byte(normalizeLineEndingsString(signedText))

				block, _ := pem.Decode([]byte(restText))
				if block == nil || block.Type != textModeSigPem {
					l.Fatal("Signature not found.")
				}
				z, _ := zlib.NewReader(bytes.NewReader(block.Bytes))
				sigBlock, err = io.ReadAll(z)
				check(err, "Damaged signature.")

			} else {
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
			}

		} else {
			sigBlock = slurpFile(sigFile)
		}

		if !textMode {
			if !bytes.Equal(sigBlock[:len(sigHeader)], []byte(sigHeader)) {
				l.Fatal("Missing signature header, file probably isn't signed.")
			}
		}

		// Now we need to unmarshal the sig.
		var sigData SigBlock
		if textMode {
			err = cbor.Unmarshal(sigBlock, &sigData)
		} else {
			err = cbor.Unmarshal(sigBlock[len(sigHeader):], &sigData)
		}
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

		var cert *x509.Certificate
		cacheCertFile := filepath.Join(dataDir, sigData.Callsign+".der")
		if len(sigData.Certificate) > 0 {
			cert, err = x509.ParseCertificate(sigData.Certificate)
			check(err, "Could not parse the public key included with signature:")
			// Save it in the cache.
			err = os.WriteFile(cacheCertFile, cert.Raw, 0666)
			check(err, "Could not save public key to cache.")
		} else {
			// Else we try to read one from our cache.
			crtFile, err := os.ReadFile(cacheCertFile)
			check(err, "The signature does not include a public key, and I could not read one from cache.")
			cert, err = x509.ParseCertificate(crtFile)
			check(err, "Could not parse a certificate in cache.")
		}

		// Build the pool of intermediary certs supplied with the sig.
		extraCerts := x509.NewCertPool()
		if dumpDer {
			l.Println("Will attempt to save included intermediate certificates...")
		}
		for idx, der := range sigData.CA {
			crt, err := x509.ParseCertificate(der)
			check(err, "Could not parse intermediate certificate authority data:")
			extraCerts.AddCert(crt)
			if dumpDer {
				// Save certificates: This is the easy way to send me a LoTW certificate
				// lotw-trust does not yet recognize.
				certName := fmt.Sprintf("%s_%d.der", sigData.Callsign, idx)
				if err := os.WriteFile(
					certName,
					crt.Raw, 0666); err != nil {
					l.Fatal(err)
				}
				l.Println("Saved", certName)
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
			// LoTW intermediate certificates are *expected* to expire during
			// the public key's lifetime, so we must verify it with time
			// set to the day it was issued, rather than any other day,
			// otherwise verification can fail for no good reason.
			CurrentTime: cert.NotBefore.Add(time.Hour),
			KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		})
		check(err, "Failed to verify public key:")

		displayTime, _ := verificationTime.UTC().MarshalText()
		l.Println("Signed by:", getCallsign(*cert), "on", string(displayTime))
		if textMode {
			textData := []byte(fmt.Sprintf("\n-----VERIFIED BY LOTW-TRUST-----\nSigned by: %s on %s",
				getCallsign(*cert),
				string(displayTime)))
			fileData = append(fileData, textData...)
		}

		saveFile(outputFile, fileData)

		// Everything went fine!
		os.Exit(0)

	} else {
		flaggy.ShowHelp("")
	}

}
