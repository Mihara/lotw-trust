#!/bin/bash

rm root/* intermediate/* user/*

touch root/index.txt
echo 01 >root/serial
touch intermediate/index.txt
echo 01 >intermediate/serial

echo === Generating root CA.
openssl genrsa -out root/ca.key.pem 4096
openssl req -config ./openssl.conf \
	-key root/ca.key.pem \
	-new -x509 -days 7300 -sha512 -extensions v3_ca \
	-out root/ca.cert.pem \
	-subj "/C=US/ST=CT/L=Pseudocity/O=Fake American Radio Relay League/OU=Logbook of the World Mockup/CN=Logbook of the World Root CA Mockup/emailAddress=lotw@example.com"

echo === Generating Intermediate CA CSR
openssl genrsa -out intermediate/ca.key.pem 2048
openssl req -config ./openssl.conf -new -sha256 \
	-key intermediate/ca.key.pem \
	-out intermediate/ca.csr.pem \
	-subj "/C=US/ST=CT/L=Pseudocity/O=Fake American Radio Relay League/OU=Logbook of the World Mockup/CN=Logbook of the World Production CA Mockup/emailAddress=lotw@example.com"

echo === Signing the Intermediate CA CSR with Root CA.
openssl ca -config ./openssl.conf -extensions v3_intermediate_ca \
	-days 6000 -notext -md sha256 -batch \
	-in intermediate/ca.csr.pem \
	-out intermediate/ca.cert.pem

echo === Generating a callsign CSR.
openssl genrsa -out user/user.key.pem 2048
openssl req -config ./openssl.conf -new -sha256 \
	-subj "/CN=John Doe/emailAddress=john@example.com/Callsign=N0CALL" \
	-key user/user.key.pem \
	-out user/user.csr.pem

echo === Signing the callsign CSR with Intermediate CA.
openssl ca -config openssl.conf -name CA_intermediate -batch \
	-extensions user_cert -days 5000 -notext -md sha256 \
	-in user/user.csr.pem \
	-out user/user.cert.pem

echo === Saving results.

KEYS=../keys
CACHE=$KEYS/cache

mkdir -p $CACHE/roots
openssl x509 -in root/ca.cert.pem -outform der -out $CACHE/roots/mockup.der
mkdir -p $CACHE/chain
openssl x509 -in intermediate/ca.cert.pem -outform der -out $CACHE/chain/mockup.der

# Now the fun part, making a pkcs12 file...
openssl pkcs12 -export -out $KEYS/N0CALL.p12 \
    -password pass:changeme \
	-inkey user/user.key.pem \
	-in user/user.cert.pem \
	-certfile intermediate/ca.cert.pem

echo === Done!
