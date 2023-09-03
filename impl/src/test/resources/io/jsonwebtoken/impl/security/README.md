## Test Key Files

All test key files in this directory were generated with `openssl` version 3 or greater by executing the `genkeys` 
script in this directory.  For example:
    
    $ openssl version
    OpenSSL 3.1.2 1 Aug 2023 (Library: OpenSSL 3.1.2 1 Aug 2023)
    $ ./genkeys

The `genkeys` script creates, for each relevant JWA standard algorithm ID:

  1. A (non-password-protected) PKCS8 private key, e.g. `RS256.pkcs8.pem`
  2. It's complement public key as an X.509 public key .pem file, e.g. `RS256.pub.pem`
  3. A self-signed X.509 certificate for the associated key valid for 1000 years, e.g. `RS256.crt.pem`

Each file name is prefixed with the JWA (signature or curve) algorithm identifier, allowing for easy file lookup
based on the `SignatureAlgorithm#getId()` or `EdwardsCurve#getId()` value when authoring tests.

> **Warning**
>
> Naturally, these files are intended for testing purposes only and should never be used in a production system.

