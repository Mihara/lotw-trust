# lotw-trust

⚠️ **WARNING** ⚠️

This is highly experimental.

Do not use this program for anything critical. Right now it's still very much an evening project waiting for feedback from people trying to use it. The text mode format in particular is probably not stable.

Please experiment with it, that's the right word.

## What is it?

**TLDR**: This is a program that allows you to sign any file with the private key you get when you sign up with the [Logbook of the World](https://lotw.arrl.org/). It also allows *anyone* to verify such a signature and determine your callsign.

This is all it does, this is all it *should* be doing, and if it proves sufficiently reliable, this can open up many opportunities for doing things remotely over the radio.

If you don't know what Logbook of the World is, you probably don't care, feel free to resume your doomscrolling.

**Long version**: I have noticed that LoTW is the only QSL verification service that permits one to send the logs in without having internet access at all. The process involves cryptographically signing individual records within a specially formulated [ADIF-like](https://www.adif.org/) log file, sticking the public key and signatures in extra fields in the ADIF structure. The resulting `.tq8` file is a gzip-compressed ADIF file with extra bits, and thus is legal to send in the clear over the air, if you agree that cryptographic signatures are legal to send over the air when the actual data is unencrypted -- most people do, but to my knowledge this hasn't actually been tested with various regulatory bodies.

And LoTW *does* accept it over the air: careful reading of the LoTW website indicates that you can email signed files to lotw-logs@arrl.org -- where they will presumably be processed. Assuming you set up [Winlink](https://www.winlink.org/) properly, sending email without having Internet access in any way is a solved problem.

You could apply the same trick to other web and email-based services, like, for example, allow people to post in their accounts on your Mastodon instance by sending in signed emails, but you would require a central authority matching people's public keys to their accounts -- or at least callsigns, if you're serious about it. Which is presumably why nobody bothered so far.

Fortunately, we can exploit the existing one: Logbook of the World is the biggest QSL verification service in the world and has many thousands of users who already have public keys. It's just a tooling problem.

This project is an attempt to make that as easy to set up for a service owner as possible, by providing them with a simple, one-executable tool to sign and verify a file. There might be a GUI program to go with it later if necessary, but it should be trivial to cook up something using existing tools layering them over this executable.

## Caveats

### On the matter of LoTW root certificates

[Instructions describing how to verify a tq8 file](https://lotw.arrl.org/lotw-help/developer-tq8/) claim that *"A Digitally Signed Log file can be used to establish proof of identify"* -- which is true, but only to a point. While the steps described are sufficient to verify that the signed file has not been damaged -- that is, that the included public key matches the secret key that was used to sign the records therein -- it does not describe how to verify that the included public key has in fact been issued by LoTW.

LoTW does not currently *publish* enough information for us to do that latter verification independently. It's not that it doesn't exist, but you have to go fishing for it.

To simplify things, a public key infrastructure with a central certificate authority typically works kind of like this:

1. There's a Big Master Key. It is stored on very stable media -- occasionally, simply printed out -- in a safe somewhere, and only ever used to produce the next layer in the hierarchy of keys:
2. There are a bunch of production keys, which have much shorter lifetimes written into their structure, signed by the Big Master Key. These are used on computers that do the day-to-day signing of keys that will actually be used.
3. The actual keys the end-users use are signed by the keys from #2.

To verify that a key on layer #3 is what it says it is, you need to follow the chain of signatures to the Big Master Key in #1. Which is trivial, when the public parts of all of these keys are published in well-known locations -- or, as is more common, the public part of the #1 key is published, *(usually, it is included with other such keys that come with your browser, hundreds of them)* and the public part of #2 key is included with #3 wherever you got the signed piece of data -- that is, arrives as you establish the HTTPS session. This is how most SSL certificates all over the Internet work.

This is not quite so with LoTW, where `.tq8` files only include your own public key, that is, layer #3. It is signed with a layer #2 key, but that doesn't do you much good if you don't have a copy to verify against.

The only place where I found the requisite #2 and #1 layer public keys was my own `.tq6` file that arrived from LoTW with my certificate -- there is no obvious way it's published on their website. I emailed LoTW to inquire about them, and they did not reply so far.

As a result, if LoTW makes a new layer #2 key after you got your layer #3 key and received the corresponding `.tq6` key file, the data you possess will be insufficient to verify the authenticity of a `.tq8` file signed by a person who got their `.tq6` later than you. The way their layer #2 key expiry times are set, this inevitably happens.

`lotw-trust` attempts to work around this by keeping a list of layer #1 and #2 keys known to belong to LoTW, -- that is, I took them from *my* `.tq6` file, check the [roots directory](roots) -- and, when signing things, packing every public key that comes in your `.tq6` file that it hasn't seen before in with the signature. This bloats the signature size, and is best avoided.

To make matters more complicated, the #1 Big Master Key is also not eternal, and has an expiry time measured in decades -- the current one expires in 2025. It isn't signed by the key from the previous decade either, so you definitely will not be able to produce an unbroken chain of keys to known keys past 2025, when the current one expires, unless the new key surfaces in trustworthy data earlier than that.

It would be a lot smoother if I can get LoTW to publish their public keys properly. Otherwise, I anticipate that `lotw-trust` will need to be updated on average no less than once a year to keep working, which will be a hassle for service owners.

### Certificate revocation

There is currently no way for us to know if a user's certificate has been revoked or not. LoTW does not expose this information publicly anywhere, so you can only know if it expired, because that's written inside the certificate itself. I doubt they have set up the machinery for revoking certificates at all, in fact.

Similarly, there is no way to prevent someone from using an expired certificate, since they can set the clock to what they want.

### General caveats

I am not a cryptographer, I am a sociologist. Golang is not my best language, it's just the one that got me the result the quickest, while still allowing to easily make a cross-platform tool.

As a result, it's not idiot proof even to my lax standards, not well written, has nondescript error messages, and is in general unpolished.

I am also not certain I fully understand what I am doing. The way I use standard cryptographic primitives could be laughably wrong and I wouldn't know without someone else telling me.

## Usage

* `lotw-trust sign <your .p12 file> <input file> <output file>` to produce a signed file.
* `lotw-trust verify <input file> <output file>` to verify a signed file and produce the one without a signature block at the end. Will print the callsign of the signer and the date of signing to stderr.

You can get a `.p12` file with your private key and all the associated public keys by exporting your certificate from tQSL, the same way you would do it for uploading to clublog.org or QRZ.com

See `lotw-trust --help` and `lotw-trust <command> --help` for further options.

The signature block tries to be compact, *(about ~1500 bytes if it doesn't need to include any extra layer #2 keys, ~1000 bytes compressed, can't be much shorter than that)* and is appended to the end of the file by default. For a good number of file formats, extra data tacked onto the end will not have any effect on the way their native programs process them: `zip` files unpack just as they did, `png` and `jpg` files remain viewable, and only plain text formats will suffer from the appearance of a binary blob on the end.

It's possible to save the signature block to a separate file, verify such a signature, as well as read and write data from stdin and to stdout with further command line options.

`lotw-trust sign -a <input file> <output file>` will save an abbreviated version of the signature block, that only contains the signature itself and some glue, which saves you about ~1000 bytes of message size. To verify that, the recipient must have *previously* verified a message signed with that public key -- they get cached for just such an occasion.

Notice that while public keys get cached, intermediate certificates do not, and if your signing situation results in bundling intermediate certificates, I would very much like to see them. To save them, you can use `lotw-trust verify -d <input file>` and email the files that it dumps to me.

`lotw-trust sign -t` and `lotw-trust verify -t` will treat the file as text, resulting in an ASCII-armor style file format that you could, in theory, stick into a pipeline in Winlink to automatically sign messages you send. Trying to sign binary files with this flag will produce ugly results, but will not necessarily fail.

## Installation and compilation

This is a [Go](https://go.dev/) program, so this should be easy enough, provided you have a working Go installation:

    go install github.com/Mihara/lotw-trust@latest

It was written with go 1.20.5 and I currently don't know what's the minimum version requirement. Binaries for a number of platforms are provided in the releases section.

## Plans for future development

As of this moment, this tool is feature complete. Now it needs to become bug-free and formats need to stabilize. Please stress-test and torture it.

Alternatively it could be completely forgotten as most innovations usually are. It's not like radio didn't work without all that before.

## License

This program is released under the terms of MIT license. See the full text in [LICENSE](LICENSE)
