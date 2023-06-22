#!/bin/bash

# This is a preliminary smoke test engine, and not a proper integration test framework.
# Yet. It lets people run tests without ever touching their real key file though.

CACHE=testcases/keys/cache
KEY=testcases/keys/N0CALL.p12
SRC=testcases/files
DST=testcases/results

# Straightforward signature.
go run *.go sign -c $CACHE -p changeme $KEY $SRC/sstv.jpg $DST/sstv-signed.jpg
go run *.go verify -c $CACHE $DST/sstv-signed.jpg $DST/sstv-unsigned.jpg
cmp -l $SRC/sstv.jpg $DST/sstv-unsigned.jpg

# Uncompressed signature.
go run *.go sign -c $CACHE -p changeme -u -a $KEY $SRC/sstv.jpg $DST/sstv-signed-unc.jpg
go run *.go verify -c $CACHE $DST/sstv-signed-unc.jpg $DST/sstv-unsigned.jpg
cmp -l $SRC/sstv.jpg $DST/sstv-unsigned.jpg

# Text mode signing.
go run *.go sign -t -c $CACHE -p changeme $KEY $SRC/lipsum.txt $DST/lipsum-signed.txt
go run *.go verify -t -c $CACHE $DST/lipsum-signed.txt $DST/lipsum-unsigned.txt
