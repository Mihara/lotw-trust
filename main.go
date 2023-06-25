/*
Copyright (c) 2023 by Eugene Medvedev (R2AZE)

Use of this source code is governed by an MIT-style
license that can be found in the LICENSE file or at
https://opensource.org/licenses/MIT.
*/

package main

import (
	"bytes"
	"compress/zlib"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"embed"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"runtime"
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

const textModeHeader = "-----LOTW-TRUST MESSAGE-----"
const textModeFooter = "-----BEGIN LOTW-TRUST SIG-----"
const textModeEnding = "-----END LOTW-TRUST SIG-----"
const textModeSigPem = "LOTW-TRUST SIG"

// Binary mode header is the same with extra newlines.
const sigHeader = "\n" + textModeSigPem + "\n"

var signCmd *flaggy.Subcommand
var verifyCmd *flaggy.Subcommand
var l *log.Logger

var keyFile string
var keyPass string
var omitCert bool
var textMode bool
var uncSig bool
var inputFile string
var outputFile string
var sigFile string

var dataDir string
var chainCacheDir string
var rootsCacheDir string

// SigBlock is a struct containing the signature and associated data.
// This structure is meant to be stable from here on out.
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

	keyPass = ""

	flaggy.SetName("lotw-trust")
	flaggy.SetDescription(fmt.Sprint("Sign and verify arbitrary files with your LoTW tQSL signing key. \nversion ", version))

	flaggy.DefaultParser.AdditionalHelpAppend = `
Copyright © 2023 Eugene Medvedev (R2AZE).
See the source code at: https://github.com/Mihara/lotw-trust
Released under the terms of MIT license.`

	flaggy.String(&dataDir, "c", "cachedir", "Key cache directory")

	// Create the subcommand
	signCmd = flaggy.NewSubcommand("sign")
	signCmd.Description = "Sign a file with your LoTW key."
	signCmd.AddPositionalValue(&keyFile, "CALLSIGN.p12", 1, true, "Your LoTW signing key.")
	signCmd.String(&keyPass, "p", "password", "Password for unlocking the key, if required.")
	signCmd.String(&sigFile, "s", "sig_file", "Save the signature block into a separate file. You can use '=' to send it to standard output.")
	signCmd.Bool(&textMode, "t", "textmode", "Treat the file as readable text and produce a human-readable signature.")
	signCmd.Bool(&uncSig, "u", "uncompressed", "Do not compress the signature block. Use it when you are compressing the whole file with something better later on.")
	signCmd.Bool(&omitCert, "a", "abbreviate", "Save a shorter version of signature block that does not include public keys.")
	signCmd.AddPositionalValue(&inputFile, "INPUT", 2, true, "Input file to be signed. '=' to read from standard input.")
	signCmd.AddPositionalValue(&outputFile, "OUTPUT", 3, false, "Output file. '=' to write to standard output.")

	verifyCmd = flaggy.NewSubcommand("verify")
	verifyCmd.Description = "Verify a file signed with a LoTW key."
	verifyCmd.Bool(&textMode, "t", "textmode", "The input contains a text mode signature, and must be treated as such.")
	verifyCmd.String(&sigFile, "s", "sig_file", "Read the signature block from a separate file. You can use '=' to read it from standard input.")
	verifyCmd.AddPositionalValue(&inputFile, "INPUT", 1, true, "Input file to be verified. '=' to read from standard input.")
	verifyCmd.AddPositionalValue(&outputFile, "OUTPUT", 2, false, "Output file. '=' to write to standard output.")

	flaggy.AttachSubcommand(signCmd, 1)
	flaggy.AttachSubcommand(verifyCmd, 1)

	flaggy.SetVersion(version)
	flaggy.Parse()

	// This needs to be done here, after we've parsed the flags.
	chainCacheDir = filepath.Join(dataDir, "chain")
	rootsCacheDir = filepath.Join(dataDir, "roots")
	// Yeah, that is a pythonism.
	for _, d := range []string{dataDir, chainCacheDir, rootsCacheDir} {
		if _, err := os.Stat(d); os.IsNotExist(err) {
			err := os.MkdirAll(d, os.ModeDir|0o755)
			check(err, "Could not create or open "+d)
		}
	}

}

func certInList(a []*x509.Certificate, x *x509.Certificate) bool {
	for _, n := range a {
		if bytes.Equal(x.SubjectKeyId, n.SubjectKeyId) {
			return true
		}
	}
	return false
}

func check(e error, message any) {
	if e != nil {
		l.Fatal("ERROR: ", message, " ", e)
	}
}

func die(message ...any) {
	l.Fatal("ERROR: ", message)
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
				die("Error while saving a file:", err)
			}
		} else {
			if err := os.WriteFile(filename, fileData, 0666); err != nil {
				die("Error while saving a file:", err)
			}
		}
	}
}

func detectNewline(text string) string {
	// Detect a newline character based on the text file.
	// Textmode needs to introduce newlines into the text,
	// which might not be in the system-dominant
	// newlines.

	if strings.Index(text, "\r\n") > 0 {
		// Contains a single windows newline? Use windows newlines.
		return "\r\n"
	} else if strings.Index(text, "\r") > 0 {
		// Contains an osx newline - use osx newlines.
		return "\r"
	} else if strings.Index(text, "\n") > 0 {
		// Contains a linux newline - use linux newlines.
		return "\n"
	}

	// In case the input text contains none of that, return an os-based default.
	switch runtime.GOOS {
	case "windows":
		return "\r\n"
	case "darwin":
		return "\r"
	default:
		return "\n"
	}
}

func normalizeText(text []byte) []byte {
	output := normalizeTextString(string(text))
	return []byte(output)
}

func normalizeTextString(text string) string {
	// I.e. CRLF, as PGP and friends do.
	// Since we do not actually change the output format,
	// it doesn't matter that much, as long as it's consistent
	// so that a CRLF message does not get mis-verified on an LF system.
	// PGP RFCs also say to trim tabs and spaces from all lines before hashing,
	// and while it probably isn't necessary, it won't hurt either.
	const replacement = "<NEWLINE>"
	const finalNewline = "\r\n"

	var replacer = strings.NewReplacer(
		"\r\n", replacement,
		"\r", replacement,
		"\n", replacement,
	)

	var textLines []string
	for _, l := range strings.Split(replacer.Replace(text), replacement) {
		textLines = append(textLines, strings.TrimSpace(l))
	}

	// All preceding empty lines and all tailing empty lines must be ignored when signing as well.
	var tailingLines []string
	for i, s := range textLines {
		if s != "" {
			tailingLines = textLines[i:]
			break
		}
	}

	var outLines []string
	for i := len(tailingLines) - 1; i >= 0; i-- {
		if tailingLines[i] != "" {
			outLines = tailingLines[:i+1]
			break
		}
	}

	return strings.Join(outLines, finalNewline)
}

// Abstracting away compression and decompression, since that will be used multiple times.
func compress(in []byte) ([]byte, error) {
	var zlibBuf bytes.Buffer
	z, err := zlib.NewWriterLevel(&zlibBuf, zlib.BestCompression)
	if err != nil {
		return in, nil
	}
	_, err = z.Write(in)
	if err != nil {
		return in, nil
	}
	err = z.Close()
	// And if the compressed block somehow turned out bigger than the uncompressed one,
	// don't return it.
	out := zlibBuf.Bytes()
	if len(in) < len(out) {
		return in, err
	}
	return out, err
}

func uncompress(in []byte) ([]byte, error) {
	z, err := zlib.NewReader(bytes.NewReader(in))
	if err != nil {
		return in, err
	}
	out, err := io.ReadAll(z)
	return out, err
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

	// If our cache includes any extra trusted roots --
	// which would have to be placed there manually, we never save them --
	// slurp them in as well.
	// This is also what lets us use a complete dummy hierarchy of certificates for testing.
	rootFiles, _ = os.ReadDir(rootsCacheDir)
	for _, f := range rootFiles {
		if strings.HasSuffix(strings.ToLower(f.Name()), ".der") {
			der, err := os.ReadFile(filepath.Join(rootsCacheDir, f.Name()))
			check(err, "Failed to read a root certificate from cache.")
			crt, err := x509.ParseCertificate(der)
			check(err, "Failed to parse a root certificate from cache.")
			roots.AddCert(crt)
			rootCerts = append(rootCerts, crt)
		}
	}

	if signCmd.Used {
		// Signing a file
		keyData, err := os.ReadFile(keyFile)
		check(err, "Could not read the key file.")

		pKey, cert, caChain, err := pkcs12.DecodeChain(keyData, keyPass)
		check(err, "Could not make sense of the key file.")

		if time.Now().After(cert.NotAfter) {
			die("Cannot use a LoTW certificate beyond its expiry time.")
		}
		if time.Now().Before(cert.NotBefore) {
			die("Cannot use a LoTW certificate before it goes active.")
		}

		callsign := getCallsign(*cert)
		if callsign == "" {
			die("The signing key does not appear to be a LoTW key.")
		}

		// Slurp the input file...
		fileData := slurpFile(inputFile)

		signingTime := time.Now().UTC().Truncate(time.Second)

		var hashingData []byte
		dateString, _ := signingTime.MarshalText()

		if textMode {
			// In text mode, we must normalize line endings to something before hashing.
			hashingData = normalizeText(fileData)
			hashingData = append(hashingData, dateString...)
		} else {
			hashingData = append(fileData, dateString...)
		}

		var signature []byte
		switch cert.PublicKeyAlgorithm {
		case x509.RSA:
			hashed := sha256.Sum256(hashingData)
			signature, err = rsa.SignPKCS1v15(nil,
				pKey.(*rsa.PrivateKey),
				crypto.SHA256,
				hashed[:],
			)
		default:
			die("You have discovered a LoTW key of a previously unseen, unsupported type! Please email me about it.")
		}
		check(err, "Signing failure, something weird happened.")

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

		// The actual sig block is compressed with zlib to save space.
		var compressedSig []byte
		if uncSig {
			compressedSig = buf
		} else {
			compressedSig, _ = compress(buf)
		}

		sigBlock := append([]byte(sigHeader), compressedSig...)

		var savingData []byte

		if textMode {
			// Text mode makes things vastly more cumbersome.
			// PEM to the rescue!

			textData := textModeHeader
			textData += "\n" + string(fileData) + "\n"
			savingData = []byte(textData)

			displayTime, _ := sig.SigningTime.UTC().Truncate(time.Second).MarshalText()
			sigPemBlock := &pem.Block{
				Type:  textModeSigPem,
				Bytes: compressedSig,
				Headers: map[string]string{
					"Signer": sig.Callsign,
					"Date":   string(displayTime),
				},
			}

			savingData = append(savingData, pem.EncodeToMemory(sigPemBlock)...)

		} else {
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
		var rawTextHeader string
		var rawTextFooter string
		var restText string
		var found bool

		if sigFile == "" {

			if textMode {
				// Text mode makes everything more complicated on read, too.
				textData := string(fileData)
				rawTextHeader, restText, found = strings.Cut(textData, textModeHeader)
				if !found {
					die("The file does not appear to be signed in text mode.")
				}

				tailEnd := strings.LastIndex(restText, textModeFooter)
				if tailEnd < 0 {
					die("Signed message seems to have lost a chunk.")
				}
				signedText := restText[:tailEnd]

				postSig := strings.LastIndex(restText, textModeEnding)
				if postSig < 0 {
					die("Signed message appears to be missing parts of the signature.")
				}

				rawTextFooter = restText[postSig+len(textModeEnding):]

				fileData = []byte(normalizeTextString(signedText))
				// Amusingly, OSX line endings can also cause pem to fail to decode.
				// So we normalize the restText before feeding it into the decoder.
				block, _ := pem.Decode([]byte(normalizeTextString(restText)))
				if block == nil || block.Type != textModeSigPem {
					die("Signature not found.")
				}

				sigBlock, err = uncompress(block.Bytes)
				check(err, "Damaged signature.")

			} else {
				sigStart := bytes.LastIndex(fileData, []byte(sigHeader))
				if sigStart < 0 {
					die("Broken or missing signature block.")
				}
				sigBlock = fileData[sigStart:]
				fileData = fileData[:sigStart]
			}

		} else {
			sigBlock = slurpFile(sigFile)
		}

		var sigData SigBlock
		if !textMode {
			if !bytes.Equal(sigBlock[:len(sigHeader)], []byte(sigHeader)) {
				die("Could not find signature in file.")
			}
			sigBlock = sigBlock[len(sigHeader):]
			// While we're at it, try to uncompress sig block.
			sigBlock, err = uncompress(sigBlock)
			// If the sig block was never compressed, this is the error we will get,
			// so we eat it and move on.
			if !errors.Is(err, zlib.ErrHeader) {
				check(err, "Failed to decompress signature.")
			}
		}

		// Now we need to unmarshal the sig.
		err = cbor.Unmarshal(sigBlock, &sigData)
		check(err, "Could not parse signature block.")

		// We can verify the signatures on versions lower than ours, sometimes, but not vice versa.
		sigVersion, err := semver.Parse(sigData.Version)
		check(err, "Broken version number in signature block.")

		if myVersion.Compare(sigVersion) < 0 {
			die("File is signed with a newer version of lotw-trust than v", myVersion)
		}

		if myVersion.Compare(sigVersion) > 0 {
			oldVersion, _ := semver.Parse(minSupportedVersion)
			if sigVersion.Compare(oldVersion) < 0 {
				die("Cannot verify signatures made with versions older than v", minSupportedVersion)
			}
		}

		var cert *x509.Certificate

		if len(sigData.Certificate) > 0 {
			cert, err = x509.ParseCertificate(sigData.Certificate)
			check(err, "Could not parse the public key included with signature.")
		} else {
			// Else we try to read one from our cache.
			cacheCertFile := filepath.Join(dataDir, sigData.Callsign+".der")
			crtFile, err := os.ReadFile(cacheCertFile)
			check(err, "The signature does not include a public key, and I could not read one from cache.")
			cert, err = x509.ParseCertificate(crtFile)
			check(err, "Could not parse a certificate in cache.")
		}

		// Build the pool of intermediary certs supplied with the sig.
		extraCerts := x509.NewCertPool()
		for _, der := range sigData.CA {
			crt, err := x509.ParseCertificate(der)
			check(err, "Could not parse intermediate certificate authority data.")
			extraCerts.AddCert(crt)
		}
		// If we have any intermediate certificates in the cache, dump them into the pool too.
		cachedRootFiles, _ := os.ReadDir(chainCacheDir)
		for _, f := range cachedRootFiles {
			if strings.HasSuffix(strings.ToLower(f.Name()), ".der") {
				der, err := os.ReadFile(filepath.Join(chainCacheDir, f.Name()))
				check(err, "Could not read file from intermediary certificate cache.")
				crt, err := x509.ParseCertificate(der)
				check(err, "Could not parse intermediary certificate cache file "+f.Name())
				extraCerts.AddCert(crt)
			}
		}

		// Verify the actual signature.
		var hashingData []byte
		verificationTime := sigData.SigningTime.UTC().Truncate(time.Second)
		dateString, err := verificationTime.MarshalText()
		check(err, "Broken time information in signature.")
		hashingData = append(fileData, dateString...)

		// Depending on what kind of public key we got, we may need to do different things.
		switch cert.PublicKeyAlgorithm {
		case x509.RSA:
			hashed := sha256.Sum256(hashingData)
			err = rsa.VerifyPKCS1v15(
				cert.PublicKey.(*rsa.PublicKey),
				crypto.SHA256,
				hashed[:],
				sigData.Signature,
			)
		default:
			die("Unsupported signature algorithm. This shouldn't happen, which means you found a bug.")
		}

		check(err, "Failed to verify signature.")

		chains, err := cert.Verify(x509.VerifyOptions{
			Intermediates: extraCerts,
			Roots:         roots,
			// LoTW intermediate certificates are *expected* to expire during
			// the public key's lifetime, so we must verify it with time
			// set to the day it was issued, rather than any other day,
			// otherwise verification can fail for no good reason.
			CurrentTime: cert.NotBefore.Add(time.Hour),
			KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		})
		check(err, "Failed to verify public key.")

		// Since we verified everything successfully, save the certficate in the cache.
		cacheCertFile := filepath.Join(dataDir, getCallsign(*cert)+".der")
		err = os.WriteFile(cacheCertFile, cert.Raw, 0666)
		check(err, "Could not save public key to cache.")

		// If the successful verification chains contain any unknown intermediate
		// certificates, cache them as well.
		for _, chain := range chains {
			for _, c := range chain {
				if !certInList(rootCerts, c) && c.IsCA {
					cacheRootFile := filepath.Join(chainCacheDir, hex.EncodeToString(c.SubjectKeyId)+".der")
					if _, err := os.Stat(cacheRootFile); errors.Is(err, os.ErrNotExist) {
						err = os.WriteFile(cacheRootFile, c.Raw, 0666)
						check(err, "Could not save intermediate root certificate to cache.")
					}
				}
			}
		}

		displayTime, _ := verificationTime.UTC().MarshalText()
		l.Println("Signed by:", getCallsign(*cert), "on", string(displayTime))
		if textMode {
			// Text mode file output tries to preserve anything not bracketed with the "signed text"
			// markers, and instead brackets it in new ones which say the signed text was verified.
			newLine := detectNewline(string(fileData))
			fileData = bytes.Join(
				[][]byte{
					[]byte(rawTextHeader),
					[]byte("-----LOTW-TRUST SIGNED----" + newLine),
					fileData,
					[]byte(fmt.Sprintf(
						"%s-----LOTW-TRUST VERIFIED-----%sSigned by: %s on %s",
						newLine,
						newLine,
						getCallsign(*cert),
						string(displayTime))),
					[]byte(rawTextFooter),
				},
				[]byte{},
			)
		}

		saveFile(outputFile, fileData)

		// Everything went fine!
		os.Exit(0)

	} else {
		flaggy.ShowHelp("")
	}

}
