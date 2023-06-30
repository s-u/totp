# TOTP
Minimal implementation of the TOTP (Time-based One-Time Password) algorithm and a command line tool for generating the most common two-factor authentication (2FA) tokens.

## Building
The sources require `libcrypto` from OpenSSL (for the HMAC calculation). To build, type `make`. It will use `pkg-config` to determine correct flags for `libcrypto`. For any non-standard setup, edit the first lines of the `Makefile`.

## Usage
The tool itself provides a quick usage summary when run with `-h`:

```

 Usage: totp [-v] [-1] [-t <time>] [-s <step>] [-d <digits>] <key-file>
        totp [-v] [-1] [-t <time>] [-s <step>] [-d <digits>] -k <key>
        totp -h

 By default current and next token are printed with
 expiry information. Use -1 to just print the current token.
 <key-file> can be - for key input on stdin.

```
For security reasons it is not recommended to use keys on the command line, the use of `-k` is strongly discouraged (since anyone on the machine can then see your key). You can use encrypted keys by passing them from your favorite decryption tool on `stdin` with `-` as the key file.

## Details
The key is expected to be in base32 encoding - it is simply the upper-case letters and numbers after `security=` in the URL you get from your 2FA provider.

The default step (how long a token is valid) is 30 seconds, 6 digits are shown and the current timestamp is used.

Tokens for any timepoint can be generated by specifying the `<time>` value (seconds since the epoch).

This tool is intended to be minimalistic and is intended for internal and scripting use. There are many other heavy-weight tools out there with similar functionality. It uses only a single function from OpenSSL so it can be easily ported to other crypto implementations or even used without any dependencies. 
