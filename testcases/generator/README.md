# CA tree generator

The `generate_keys.sh` script builds a certificate authority structure that looks very much like LoTW's, but isn't, in addition to producing a user certificate for N0CALL. This certificate will not be recognized by `lotw-trust` unless the requisite `mockup.der` files are placed directly into the key cache -- or the key cache is pointed at the directory where they live, `testcases/keys/cache`, with `-c` command line option. This particular stunt makes it possible to use a completely fake certificate authority structure for testing purposes.

Running this script will wipe the existing structure in `testcases/generator` and start again, so signatures created with keys you had before will stop verifying.

Generally you shouldn't need to do use this again, unless LoTW does something unusual.

