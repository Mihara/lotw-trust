#!/bin/bash

env GOOS=linux GOARCH=amd64 go build -o build/lotw-trust_linux -ldflags '-s -w'
env GOOS=windows GOARCH=amd64 go build -o build/lotw-trust.exe -ldflags '-s -w'
env GOOS=darwin GOARCH=amd64 go build -o build/lotw-trust_osx -ldflags '-s -w'
env GOOS=linux GOARCH=arm64 go build -o build/lotw-trust_rpi64 -ldflags '-s -w'
