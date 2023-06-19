# lotw-trust

⚠️ **WARNING** ⚠️

This is highly experimental.

Do not use this program for anything critical. Right now it's still very much an evening project waiting for feedback from people trying to use it. The signature format is not yet stable, and changes in the near future are likely to introduce an incompatibility.

Please experiment with it, that's the right word.

## What is it?

**TLDR**: This is a program that allows you to sign any file with the private key you get when you sign up with the [Logbook of the World](https://lotw.arrl.org/). It also allows anyone to verify such a signature and determine your callsign. This is all it does, this is all it *should* be doing, and if it proves sufficiently reliable, this can open up many opportunities for doing things remotely over the radio.

If you don't know what Logbook of the World is, you probably don't care, feel free to resume your doomscrolling.

**Long version**: I have noticed that LoTW is the only QSL verification service that permits one to send the logs in without having internet access at all. The process involves cryptographically signing individual records within a specially formulated [ADIF-like](https://www.adif.org/) log file, sticking the public key and signatures in extra fields in the ADIF structure. The resulting `.tq8` file is a gzip-compressed ADIF file with extra bits, and thus is legal to send in the clear over the air, if you agree that cryptographic signatures are legal to send over the air when the actual data is unencrypted -- most people do, but to my knowledge this hasn't actually been tested with various regulatory bodies.

And LoTW *does* accept it over the air: careful reading of the LoTW website indicates that you can email signed files to lotw-logs@arrl.org -- where they will presumably be processed. Assuming you set up [Winlink](https://www.winlink.org/) properly, sending email without having Internet access in any way is a solved problem.

You could apply the same trick to other web and email-based services, like, for example, allow people to post in their accounts on your Mastodon instance by sending in signed emails, but you would require a central authority matching people's public keys to their accounts -- or at least callsigns, if you're serious about it. Which is presumably why nobody bothered so far.

Fortunately, we can exploit the existing one: Logbook of the World is the biggest QSL verification service in the world and has many thousands of users who already have public keys. It's just a tooling problem.

This project is an *(incomplete)* attempt to make that as easy to set up for a service owner as possible, by providing them with a simple, one-executable tool to sign and verify a file. There might be a GUI program to go with it later if necessary.

## Caveats

### On the matter of LoTW root certificates

[Instructions describing how to verify a tq8 file](https://lotw.arrl.org/lotw-help/developer-tq8/) claim that *"A Digitally Signed Log file can be used to establish proof of identify"* -- which is true, but only to a point. While the steps described are sufficient to verify that the signed file has not been damaged -- that is, that the included public key matches the secret key that was used to sign the records therein -- it does not describe how to verify that the included public key has in fact been issued by LoTW.

To simplify things, a public key infrastructure with a central certificate authority typically works kind of like this:

1. There's a Big Master Key. It is stored on very stable media -- occasionally, simply printed out -- in a safe somewhere, and only ever used to produce the next layer in the hierarchy of keys:
2. There are a bunch of production keys, which have much shorter lifetimes written into their structure, signed by the Big Master Key. These are used on computers that do the day-to-day signing of keys that will actually be used.
3. The actual keys the end-users use are signed by the keys from #2.

To verify that a key on layer #3 is what it says it is, you need to follow the chain of signatures to the Big Master Key in #1. Which is trivial, when the public parts of all of these keys are published in well-known locations -- or, as is more common, the public part of the #1 key is published, and the public part of #2 key is included with #3 wherever you got the signed piece of data. This is how most SSL certificates all over the Internet work, in fact.

This is not quite so with LoTW, where `.tq8` files only include your own public key, that is, layer #3. The only place where I found the requisite #2 and #1 layer public keys was my own `.tq6` file that arrived from LoTW with my certificate -- there is no obvious way it's published on their website. *(Which I am going to be writing them about the moment they let me on their lotw-devel mailing list.)* To make matters more complicated, the #1 Big Master Key is not stable, and appears to change, on average, once per decade. And the key for this decade isn't signed by the key from the previous decade either.

Which means that if LoTW made a new layer #2 key after you got your #3 key and received the corresponding `.tq6` key file, the data you posess will be insufficient to verify the authenticity of a `.tq8` file signed by a person who got their `.tq6` later than you -- not without LoTW doing this for you, which they aren't doing.

`lotw-trust` attempts to work around this by keeping a list of layer #1 and #2 keys known to belong to LoTW, -- that is, I took them from *my* `.tq6` file -- and, when signing things, packing every public key that comes in your `.tq6` file that it hasn't seen before in with the signature. However, I anticipate this will not be sufficient long term, and `lotw-trust` will need to be updated on average no less than once a year to keep working.

### Certificate revocation

There is currently no way for us to know if a user's certificate has been revoked or not. LoTW does not expose this information publicly anywhere, so you can only know if it expired, because that's written inside the certificate itself.

### Date of signing

There is currently no provision to date the signing of the file, i.e. if you check the signature of a file signed in the past after the public key used in it has expired, it will be considered invalid. I am not sure what is the correct way to deal with this just yet.

### RSA keys

`lotw-trust` currently assumes that LoTW issues and will forever issue only RSA-based x509 certificates. This is not guaranteed. In fact, it'd be better if they switched to something more modern, even if I would have to code to handle that.

### General caveats

I am not a cryptographer, I am a sociologist. Golang is not my best language, it's just the one that got me the result the quickest, while still allowing to easily make a cross-platform tool.

As a result, it's not idiot proof even to my lax standards, not well written, has nondescript error messages, and is in general unpolished.

I am also not certain I fully understand what I am doing. The way I use standard cryptographic primitives could be laughably wrong and I wouldn't know without someone else telling me.

## Usage

* `lotw-trust sign <your .p12 file> <input file> <output file>` to produce a signed file.
* `lotw-trust verify <input file> <output file>` to verify a signed file and produce the one without a signature block at the end. Will print the callsign of the signer to stderr.

You can get a `.p12` file with your private key and all the associated public keys by exporting your certificate from tQSL, the same way you would do it for uploading to clublog.org or QRZ.com

See `lotw-trust --help` and `lotw-trust <command> --help` for further options, not that there are any yet, except the one to supply a password for your `.p12` file, if you've set one for whatever reason.

The signature block tries to be compact, *(about 1500 bytes if everything is well, can't be much shorter than that)* and is appended to the end of the file. For a good number of file formats, extra data tacked onto the end will not have any effect on the way their native programs process them: `zip` files unpack just as they did, `png` and `jpg` files remain viewable, and only plaintext formats will suffer from the appearance of a binary blob on the end.

## Installation and compilation

This is a [Go](https://go.dev/) program, so this should be easy enough, provided you have a working Go installation:

    go install github.com/mihara/lotw-trust

Binaries are provided in the releases section. At the moment, it's very probable most of them don't actually run.

## Plans for future development

Since so far, every comment about this that I received has been positive, even if the number of comments have been small, here's what I'm going to do next:

1. Clean the thing up and make error messages make sense where possible.
2. Reading and writing standard input and standard output.
3. An ASCII-armor style file format specifically designed for signing text messages, so that you could in theory stick the signer inside Winlink as a filter.
4. Ability to save the signature block completely separately from the signed file and read such signatures.
5. Ability to omit the public key from the message, which should reduce the file size increase introduced by signing from ~1500 bytes to ~180, as well as the ability to cache public keys when signatures are verified. This way, you would send your first message to someone with a full signature, and subsequent ones could be abbreviated.

## License

This program is released under the terms of MIT license. See the full text in [LICENSE](LICENSE)
