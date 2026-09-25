# SPECK

An implementation of some variants of the SPECK block cipher written in Go.

## Supported Variants

|Block size|Key size|
|----------|--------|
|128|128|
|128|256|

I have decided to not ever implement 96 bit and 192 bit keys as they are pointless in my opinion, and I've never seen anyone use a 192 bit key and I feel wrong using 96 bit keys.

## References

* [The Simon and Speck Families of Lightweight Block Ciphers](https://eprint.iacr.org/2013/404.pdf)
* [SIMON and SPECK Implementation Guide](https://nsacyber.github.io/simon-speck/implementations/ImplementationGuide1.1.pdf)

## Notes

I wouldn't recommend using SPECK unless you really have to. If you need a block cipher I recommend AES-256 (see: [cipher/aes](https://pkg.go.dev/crypto/aes@go1.27.1)).

I also don't know the security of this library, so you should only use it at your own risk.