#!/bin/bash

# This is a preliminary smoke test engine, and not a proper integration test framework.
# Yet. It lets people run tests without ever touching their real key file though.
# Currently will not work properly on Windows: text mode tests assume
# starting with a Linux line endings file.

CACHE=testcases/keys/cache
KEY=testcases/keys/N0CALL.p12
SRC=testcases/files
DST=testcases/results

echo === Straightforward test: must pass.
go run *.go sign -c $CACHE -p changeme $KEY $SRC/sstv.jpg $DST/sstv-signed.jpg
go run *.go verify -c $CACHE $DST/sstv-signed.jpg $DST/sstv-unsigned.jpg
cmp -l $SRC/sstv.jpg $DST/sstv-unsigned.jpg

echo === Uncompressed signature test: must pass.
go run *.go sign -c $CACHE -p changeme -u -a $KEY $SRC/sstv.jpg $DST/sstv-signed-unc.jpg
go run *.go verify -c $CACHE $DST/sstv-signed-unc.jpg $DST/sstv-unsigned.jpg
cmp -l $SRC/sstv.jpg $DST/sstv-unsigned.jpg

echo === Detached signature test: must pass.
go run *.go sign -c $CACHE -p changeme -s $DST/sstv.jpg.sig -a $KEY $SRC/sstv.jpg 
go run *.go verify -c $CACHE -s $DST/sstv.jpg.sig $SRC/sstv.jpg

echo === Damaged file: must fail.
printf "00000c: %02x" $b_dec | xxd -r - $DST/sstv-signed.jpg
go run *.go verify -c $CACHE $DST/sstv-signed.jpg

echo === Damaged signature: must fail.
printf "0000cc: %02x" $b_dec | xxd -r - $DST/sstv.jpg.sig
go run *.go verify -c $CACHE -s $DST/sstv.jpg.sig $SRC/sstv.jpg

echo === Text mode tests -- native line endings: must pass.
go run *.go sign -t -c $CACHE -p changeme $KEY $SRC/lipsum.txt $DST/lipsum-signed.txt
go run *.go verify -t -c $CACHE $DST/lipsum-signed.txt $DST/lipsum-unsigned.txt

echo === Text mode tests -- mac line endings: must pass.
unix2mac -n $DST/lipsum-signed.txt $DST/lipsum-signed-mac.txt
go run *.go verify -t -c $CACHE $DST/lipsum-signed-mac.txt $DST/lipsum-unsigned-mac.txt

echo === Text mode tests -- dos line endings: must pass.
unix2dos -n $DST/lipsum-signed.txt $DST/lipsum-signed-dos.txt
go run *.go verify -t -c $CACHE $DST/lipsum-signed-dos.txt $DST/lipsum-unsigned-dos.txt

echo === Text mode tests -- winlink header: must pass.
go run *.go verify -t -c $CACHE $SRC/lipsum-winlink.txt $DST/lipsum-unsigned-winlink.txt
