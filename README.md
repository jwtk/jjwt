[![Build Status](https://github.com/jwtk/jjwt/actions/workflows/ci.yml/badge.svg?branch=master)](https://github.com/jwtk/jjwt/actions/workflows/ci.yml?query=branch%3Amaster)
[![Coverage Status](https://coveralls.io/repos/github/jwtk/jjwt/badge.svg?branch=master)](https://coveralls.io/github/jwtk/jjwt?branch=master)
[![Gitter](https://badges.gitter.im/jwtk/jjwt.svg)](https://gitter.im/jwtk/jjwt?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge)

# Java JWT: JSON Web Token for Java and Android

JJWT aims to be the easiest to use and understand library for creating and verifying JSON Web Tokens (JWTs) on the JVM
and Android.

JJWT is a pure Java implementation based exclusively on the [JWT](https://tools.ietf.org/html/rfc7519), 
[JWS](https://tools.ietf.org/html/rfc7515), [JWE](https://tools.ietf.org/html/rfc7516), 
[JWA](https://tools.ietf.org/html/rfc7518), [JWK](https://tools.ietf.org/html/rfc7517), 
[Octet JWK](https://www.rfc-editor.org/rfc/rfc8037),
[JWK Thumbprint](https://www.rfc-editor.org/rfc/rfc7638.html), and 
[JWK Thumbprint URI](https://www.rfc-editor.org/rfc/rfc9278.html) RFC specifications and 
open source under the terms of the [Apache 2.0 License](http://www.apache.org/licenses/LICENSE-2.0).

The library was created by [Les Hazlewood](https://github.com/lhazlewood)
and is supported and maintained by a [community](https://github.com/jwtk/jjwt/graphs/contributors) of contributors.

We've also added some convenience extensions that are not part of the specification, such as JWS compression and claim 
enforcement.

## Table of Contents

* [Features](#features)
  * [Currently Unsupported Features](#features-unsupported)
* [Community](#community)
  * [Getting Help](#help)
    * [Questions](#help-questions)
    * [Bugs and Feature Requests](#help-issues)
  * [Contributing](#contributing)
    * [Pull Requests](#contributing-pull-requests)
    * [Help Wanted](#contributing-help-wanted)
* [What is a JSON Web Token?](#overview)
  * [JWT Example](#overview-example-jwt)
  * [JWS Example](#overview-example-jws)
  * [JWE Example](#overview-example-jwe)
* [Installation](#install)
  * [JDK Projects](#install-jdk)
    * [Maven](#install-jdk-maven)
    * [Gradle](#install-jdk-gradle)
  * [Android Projects](#install-android)
    * [Dependencies](#install-android-dependencies)
    * [Proguard Exclusions](#install-android-proguard)
    * [Bouncy Castle](#install-android-bc)
  * [Understanding JJWT Dependencies](#install-understandingdependencies)
* [Quickstart](#quickstart)
* [Create a JWT](#jwt-create)
  * [Header](#jwt-header)
    * [Header Builder](#jwt-header-builder)
    * [Header Parameters](#jwt-header-params)
    * [Header Map](#jwt-header-map)
  * [Payload](#jwt-payload)
    * [Arbitrary Content](#jwt-content)
    * [Claims](#jwt-claims)
      * [Standard Claims](#jwt-claims-standard)
      * [Custom Claims](#jwt-claims-custom)
      * [Claims Instance](#jwt-claims-instance)
      * [Claims Map](#jwt-claims-map)
  * [Compression](#jwt-compression)
* [Read a JWT](#jwt-read)
  * [Static Parsing Key](#jwt-read-key)
  * [Dynamic Parsing Key Lookup](#key-locator)
    * [Custom Key Locator](#key-locator-custom)
    * [Key Locator Strategy](#key-locator-strategy)
    * [Key Locator Return Values](#key-locator-retvals)
  * [Claim Assertions](#jwt-read-claims)
  * [Accounting for Clock Skew](#jwt-read-clock)
    * [Custom Clock Support](#jwt-read-clock-custom)
  * [Decompression](#jwt-read-decompression)
* [Signed JWTs](#jws)
  * [Standard Signature Algorithms](#jws-alg)
  * [Signature Algorithm Keys](#jws-key)
    * [HMAC-SHA](#jws-key-hmacsha)
    * [RSA](#jws-key-rsa)
    * [Elliptic Curve](#jws-key-ecdsa)
    * [Creating Safe Keys](#jws-key-create)
      * [Secret Keys](#jws-key-create-secret)
      * [Asymetric Keys](#jws-key-create-asym)
  * [Create a JWS](#jws-create)
    * [Signing Key](#jws-create-key)
      * [SecretKey Formats](#jws-create-key-secret)
      * [Signature Algorithm Override](#jws-create-key-algoverride)
    * [Compression](#jws-create-compression)
  * [Read a JWS](#jws-read)
    * [Verification Key](#jws-read-key)
    * [Verification Key Locator](#jws-read-key-locator)
    * [Decompression](#jws-read-decompression)
    <!-- * [Error Handling](#jws-read-errors) -->
* [Encrypted JWTs](#jwe)
  * [JWE Encryption Algorithms](#jwe-enc)
    * [JWE Symmetric Encryption](#jwe-enc-symmetric)
  * [JWE Key Management Algorithms](#jwe-alg)
    * [JWE Standard Key Management Algorithms](#jwe-alg-standard)
      * [JWE RSA Key Encryption](#jwe-alg-rsa)
      * [JWE AES Key Encryption](#jwe-alg-aes)
      * [JWE Direct Key Encryption](#jwe-alg-dir)
      * [JWE Password-based Key Encryption](#jwe-alg-pbes2)
      * [JWE Elliptic Curve Diffie-Hellman Ephemeral Static Key Agreement](#jwe-alg-ecdhes)
  * [Create a JWE](#jwe-create)
    * [JWE Compression](#jwe-compression)
  * [Read a JWE](#jwe-read)
    * [JWE Decryption Key](#jwe-read-key)
    * [JWE Decryption Key Locator](#jwe-key-locator)
    * [ECDH-ES Decryption with PKCS11 PrivateKeys](#jwe-key-pkcs11)
    * [JWE Decompression](#jwe-read-decompression)
* [JSON Web Keys (JWKs)](#jwk)
  * [Create a JWK](#jwk-create)
  * [Read a JWK](#jwk-read)
  * [PrivateKey JWKs](#jwk-private)
    * [Private JWK `PublicKey`](#jwk-private-public)
    * [Private JWK from `KeyPair`](#jwk-private-keypair)
    * [Private JWK Public Conversion](#jwk-private-topub)
  * [JWK Thumbprints](#jwk-thumbprint)
    * [JWK Thumbprint as Key ID](jwk-thumbprint-kid)
    * [JWK Thumbprint URI](#jwk-thumbprint-uri)
  * [JWK Security Considerations](#jwk-security)
    * [JWK `toString()` Safety](#jwk-tostring)
* [Compression](#compression)
  * [Custom Compression Codec](#compression-custom)
  * [Custom Compression Codec Locator](#compression-custom-locator)
* [JSON Processor](#json)
  * [Custom JSON Processor](#json-custom)
  * [Jackson ObjectMapper](#json-jackson)
    * [Custom Claim Types](#json-jackson-custom-types)
  * [Gson](#json-gson)
* [Base64 Support](#base64)
  * [Base64 in Security Contexts](#base64-security)
    * [Base64 is not Encryption](#base64-not-encryption)
    * [Changing Base64 Characters](#base64-changing-characters)
  * [Custom Base64 Codec](#base64-custom)
* [Examples](#examples)
  * [JWS Signed with HMAC](#example-jws-hs)
  * [JWS Signed with RSA](#example-jws-rsa)
  * [JWS Signed with ECDSA](#example-jws-ecdsa)
  * [JWE Encrypted Directly with a SecretKey](#example-jwe-dir)
  * [JWE Encrypted with RSA](#example-jwe-rsa)
  * [JWE Encrypted with AES Key Wrap](#example-jwe-aeskw)
  * [JWE Encrypted with ECDH-ES](#example-jwe-ecdhes)
  * [JWE Encrypted with a Password](#example-jwe-password)
  * [SecretKey JWK](#example-jwk-secret)
  * [RSA Public JWK](#example-jwk-rsapub)
  * [RSA Private JWK](#example-jwk-rsapriv)
  * [Elliptic Curve Public JWK](#example-jwk-ecpub)
  * [Elliptic Curve Private JWK](#example-jwk-ecpriv)
  * [Edwards Elliptic Curve Public JWK](#example-jwk-edpub)
  * [Edwards Elliptic Curve Private JWK](#example-jwk-edpriv)

<a name="features"></a>
## Features

 * Fully functional on all Java 7+ JDKs and Android
 * Automatic security best practices and assertions
 * Easy to learn and read API
 * Convenient and readable [fluent](http://en.wikipedia.org/wiki/Fluent_interface) interfaces, great for IDE 
   auto-completion to write code quickly
 * Fully RFC specification compliant on all implemented functionality, tested against RFC-specified test vectors
 * Stable implementation with over 1,100+ tests and enforced 100% test code coverage.  Every single method, statement 
   and conditional branch variant in the entire codebase is tested and required to pass on every build.
 * Creating, parsing and verifying digitally signed compact JWTs (aka JWSs) with all standard JWS algorithms:
   
   | Identifier | Signature Algorithm                               |
   |------------|-------------------------------------------------------------------|
   | `HS256`    | HMAC using SHA-256                                                |
   | `HS384`    | HMAC using SHA-384                                                |
   | `HS512`    | HMAC using SHA-512                                                |
   | `ES256`    | ECDSA using P-256 and SHA-256                                     |
   | `ES384`    | ECDSA using P-384 and SHA-384                                     |
   | `ES512`    | ECDSA using P-521 and SHA-512                                     |
   | `RS256`    | RSASSA-PKCS-v1_5 using SHA-256                                    |
   | `RS384`    | RSASSA-PKCS-v1_5 using SHA-384                                    |
   | `RS512`    | RSASSA-PKCS-v1_5 using SHA-512                                    |
   | `PS256`    | RSASSA-PSS using SHA-256 and MGF1 with SHA-256<sup><b>1</b></sup> |
   | `PS384`    | RSASSA-PSS using SHA-384 and MGF1 with SHA-384<sup><b>1</b></sup> |
   | `PS512`    | RSASSA-PSS using SHA-512 and MGF1 with SHA-512<sup><b>1</b></sup> |
   | `EdDSA`    | Edwards-curve Digital Signature Algorithm<sup><b>2</b></sup>      |

   <sup><b>1</b>. Requires Java 11 or a compatible JCA Provider (like BouncyCastle) in the runtime classpath.</sup>

   <sup><b>2</b>. Requires Java 15 or a compatible JCA Provider (like BouncyCastle) in the runtime classpath.</sup>

 * Creating, parsing and decrypting encrypted compact JWTs (aka JWEs) with all standard JWE encryption algorithms:
 
   | Identifier                       | Encryption Algorithm                                                                                                     |
   |----------------------------------|--------------------------------------------------------------------------------------------------------------------------|
   | <code>A128CBC&#8209;HS256</code> | [AES_128_CBC_HMAC_SHA_256](https://www.rfc-editor.org/rfc/rfc7518.html#section-5.2.3) authenticated encryption algorithm |
   | `A192CBC-HS384`                  | [AES_192_CBC_HMAC_SHA_384](https://www.rfc-editor.org/rfc/rfc7518.html#section-5.2.4) authenticated encryption algorithm |
   | `A256CBC-HS512`                  | [AES_256_CBC_HMAC_SHA_512](https://www.rfc-editor.org/rfc/rfc7518.html#section-5.2.5) authenticated encryption algorithm |
   | `A128GCM`                        | AES GCM using 128-bit key<sup><b>3</b></sup>                                                                             |
   | `A192GCM`                        | AES GCM using 192-bit key<sup><b>3</b></sup>                                                                             |
   | `A256GCM`                        | AES GCM using 256-bit key<sup><b>3</b></sup>                                                                             |
   
   <sup><b>3</b>. Requires Java 8 or a compatible JCA Provider (like BouncyCastle) in the runtime classpath.</sup>

 * All Key Management Algorithms for obtaining JWE encryption and decryption keys: 
   
   | Identifier           | Key Management Algorithm                                                      |
   |----------------------|-------------------------------------------------------------------------------|   
   | `RSA1_5`             | RSAES-PKCS1-v1_5                                                              |
   | `RSA-OAEP`           | RSAES OAEP using default parameters                                           |
   | `RSA-OAEP-256`       | RSAES OAEP using SHA-256 and MGF1 with SHA-256                                |
   | `A128KW`             | AES Key Wrap with default initial value using 128-bit key                     |
   | `A192KW`             | AES Key Wrap with default initial value using 192-bit key                     |
   | `A256KW`             | AES Key Wrap with default initial value using 256-bit key                     |
   | `dir`                | Direct use of a shared symmetric key as the CEK                               |
   | `ECDH-ES`            | Elliptic Curve Diffie-Hellman Ephemeral Static key agreement using Concat KDF |
   | `ECDH-ES+A128KW`     | ECDH-ES using Concat KDF and CEK wrapped with "A128KW"                        |
   | `ECDH-ES+A192KW`     | ECDH-ES using Concat KDF and CEK wrapped with "A192KW"                        |
   | `ECDH-ES+A256KW`     | ECDH-ES using Concat KDF and CEK wrapped with "A256KW"                        |
   | `A128GCMKW`          | Key wrapping with AES GCM using 128-bit key<sup><b>4</b></sup>                |
   | `A192GCMKW`          | Key wrapping with AES GCM using 192-bit key<sup><b>4</b></sup>                |
   | `A256GCMKW`          | Key wrapping with AES GCM using 256-bit key<sup><b>4</b></sup>                |
   | `PBES2-HS256+A128KW` | PBES2 with HMAC SHA-256 and "A128KW" wrapping<sup><b>4</b></sup>              |
   | `PBES2-HS384+A192KW` | PBES2 with HMAC SHA-384 and "A192KW" wrapping<sup><b>4</b></sup>              |
   | <code>PBES2&#8209;HS512&plus;A256KW</code> | PBES2 with HMAC SHA-512 and "A256KW" wrapping<sup><b>4</b></sup> |
      
   <sup><b>4</b>. Requires Java 8 or a compatible JCA Provider (like BouncyCastle) in the runtime classpath.</sup>

 * Creating, parsing and verifying JSON Web Keys (JWKs) in all standard JWA key formats using native Java `Key` types:
   
   | JWK Key Format             | Java `Key` Type                    | JJWT `Jwk` Type   |
   |----------------------------|------------------------------------|-------------------|
   | Symmetric Key              | `SecretKey`                        | `SecretJwk`       |
   | Elliptic Curve Public Key  | `ECPublicKey`                      | `EcPublicJwk`     |
   | Elliptic Curve Private Key | `ECPrivateKey`                     | `EcPrivateJwk`    |
   | RSA Public Key             | `RSAPublicKey`                     | `RsaPublicJwk`    |
   | RSA Private Key            | `RSAPrivateKey`                    | `RsaPrivateJwk`   |
   | XDH Private Key            | `XECPublicKey`<sup><b>5</b></sup>  | `OctetPublicJwk`  |
   | XDH Private Key            | `XECPrivateKey`<sup><b>5</b></sup> | `OctetPrivateJwk` |
   | EdDSA Public Key           | `EdECPublicKey`<sup><b>6</b></sup> | `OctetPublicJwk`  |
   | EdDSA Private Key          | `EdECPublicKey`<sup><b>6</b></sup> | `OctetPrivateJwk` |

   <sup><b>5</b>. Requires Java 11 or a compatible JCA Provider (like BouncyCastle) in the runtime classpath.</sup>

   <sup><b>6</b>. Requires Java 15 or a compatible JCA Provider (like BouncyCastle) in the runtime classpath.</sup>

 * Convenience enhancements beyond the specification such as
    * Payload compression for any large JWT, not just JWEs
    * Claims assertions (requiring specific values)
    * Claim POJO marshaling and unmarshalling when using a compatible JSON parser (e.g. Jackson)
    * Secure Key generation based on desired JWA algorithms
    * and more...
    
<a name="features-unsupported"></a>
### Currently Unsupported Features

* [Non-compact](https://tools.ietf.org/html/rfc7515#section-7.2) serialization and parsing.

This feature may be implemented in a future release.  Community contributions are welcome!

<a name="community"></a>
## Community

<a name="help"></a>
### Getting Help

If you have trouble using JJWT, please first read the documentation on this page before asking questions.  We try 
very hard to ensure JJWT's documentation is robust, categorized with a table of contents, and up to date for each 
release.

<a name="help-questions"></a>
#### Questions

If the documentation or the API JavaDoc isn't sufficient, and you either have usability questions or are confused
about something, please [ask your question here](https://github.com/jwtk/jjwt/discussions/new?category=q-a). However:

**Please do not create a GitHub issue to ask a question.**  

We use GitHub Issues to track actionable work that requires changes to JJWT's design and/or codebase.  If you have a 
usability question, instead please 
[ask your question here](https://github.com/jwtk/jjwt/discussions/new?category=q-a), and we can convert that to an 
issue if necessary.

**If a GitHub Issue is created that does not represent actionable work for JJWT's codebase, it will be promptly 
closed.**

<a name="help-issues"></a>
#### Bugs, Feature Requests, Ideas and General Discussions

If you do not have a usability question and believe you have a legitimate bug or feature request, 
please [discuss it here](https://github.com/jwtk/jjwt/discussions) **_FIRST_**. Please do a quick search first to 
see if an existing discussion related to yours exist already and join that existing discussion if necesary.

If you feel like you'd like to help fix a bug or implement the new feature yourself, please read the Contributing 
section next before starting any work.

<a name="contributing"></a>
### Contributing

<a name="contributing-pull-requests"></a>
#### Pull Requests

Simple Pull Requests that fix anything other than JJWT core code (documentation, JavaDoc, typos, test cases, etc) are 
always appreciated and have a high likelihood of being merged quickly. Please send them!

However, if you want or feel the need to change JJWT's functionality or core code, please do not issue a pull request 
without [starting a new JJWT discussion](https://github.com/jwtk/jjwt/discussions) and discussing your desired 
changes **first**, _before you start working on it_.

It would be a shame to reject your earnest and genuinely-appreciated pull request if it might not align with the 
project's goals, design expectations or planned functionality.  We've sadly had to reject large PRs in the past because
they were out of sync with project or design expectations - all because the PR author didn't first check in with 
the team first before working on a solution.

So, please [create a new JJWT discussion](https://github.com/jwtk/jjwt/discussions) first to discuss, and then we 
can see easily convert the discussion to an issue and then see if (or how) a PR is warranted.  Thank you!

<a name="contributing-help-wanted"></a>
#### Help Wanted

If you would like to help, but don't know where to start, please visit the 
[Help Wanted Issues](https://github.com/jwtk/jjwt/labels/help%20wanted) page and pick any of the 
ones there, and we'll be happy to discuss and answer questions in the issue comments.

If any of those don't appeal to you, no worries! Any help you would like to offer would be 
appreciated based on the above caveats concerning [contributing pull reqeuests](#contributing-pull-requests). Feel free
to [discuss or ask questions first](https://github.com/jwtk/jjwt/discussions) if you're not sure. :)

<a name="overview"></a>
## What is a JSON Web Token?

JSON Web Token (JWT) is a _general-purpose_ text-based messaging format for transmitting information in a 
compact and secure way.  Contrary to popular belief, JWT is not just useful for sending and receiving identity tokens 
on the web - even if that is the most common use case.  JWTs can be used as messages for _any_ type of data.

A JWT in its simplest form contains two parts:

  1. The primary data within the JWT, called the `payload`, and
  2. A JSON `Object` with name/value pairs that represent metadata about the `payload` and the 
     message itself, called the `header`.

A JWT `payload` can be absolutely anything at all - anything that can be represented as a byte array, such as Strings, 
images, documents, etc.

But because a JWT `header` is a JSON `Object`, it would make sense that a JWT `payload` could also be a JSON 
`Object` as well. In many cases, developers like the `payload` to be JSON that 
represents data about a user or computer or similar identity concept. When used this way, the `payload` is called a 
JSON `Claims` object, and each name/value pair within that object is called a `claim` - each piece of information 
within 'claims' something about an identity.

And while it is useful to 'claim' something about an identity, really anyone can do that. What's important is that you 
_trust_ the claims by verifying they come from a person or computer you trust.

A nice feature of JWTs is that they can be secured in various ways. A JWT can be cryptographically signed (making it 
what we call a [JWS](https://tools.ietf.org/html/rfc7515)) or encrypted (making it a 
[JWE](https://tools.ietf.org/html/rfc7516)).  This adds a powerful layer of verifiability to the JWT - a
JWS or JWE recipient can have a high degree of confidence it comes from someone they trust
by verifying a signature or decrypting it. It is this feature of verifiability that makes JWT a good choice
for sending and receiving secure information, like identity claims.

Finally, JSON with whitespace for human readability is nice, but it doesn't make for a very efficient message
format.  Therefore, JWTs can be _compacted_ (and even compressed) to a minimal representation - basically 
Base64URL-encoded strings - so they can be transmitted around the web more efficiently, such as in HTTP headers or URLs.

<a name="overview-example-jwt"></a>
### JWT Example

Once you have a `payload` and `header`, how are they compacted for web transmission, and what does the final JWT 
actually look like? Let's walk through a simplified version of the process with some pseudocode:

1. Assume we have a JWT with a JSON `header` and a simple text message payload:

   **header**
   ```
   {
     "alg": "none"
   }
   ```

   **payload**
   ```
   The true sign of intelligence is not knowledge but imagination.
   ```

2. Remove all unnecessary whitespace in the JSON:

   ```groovy
   String header = '{"alg":"none"}'
   String payload = 'The true sign of intelligence is not knowledge but imagination.'
   ```

3. Get the UTF-8 bytes and Base64URL-encode each:

   ```groovy
   String encodedHeader = base64URLEncode( header.getBytes("UTF-8") )
   String encodedPayload = base64URLEncode( payload.getBytes("UTF-8") )
   ```

4. Join the encoded header and claims with period ('.') characters:

   ```groovy
   String compact = encodedHeader + '.' + encodedPayload + '.'
   ```

The final concatenated `compact` JWT String looks like this:

```
eyJhbGciOiJub25lIn0.VGhlIHRydWUgc2lnbiBvZiBpbnRlbGxpZ2VuY2UgaXMgbm90IGtub3dsZWRnZSBidXQgaW1hZ2luYXRpb24u.
```

This is called an 'unprotected' JWT because no security was involved - no digital signatures or encryption to
'protect' the JWT to ensure it cannot be changed by 3rd parties.

If we wanted to digitally sign the compact form so that we could at least guarantee that no-one changes the data 
without us detecting it, we'd have to perform a few more steps, shown next.

<a name="overview-example-jws"></a>
### JWS Example

Instead of a plain text payload, the next example will use probably the most common type of payload - a JSON claims
`Object` containing information about a particular identity.  We'll also digitally sign the JWT to ensure it
cannot be changed by a 3rd party without us knowing.

1. Assume we have a JSON `header` and a claims `payload`:

   **header**
   ```json
   {
     "alg": "HS256"
   }
   ```

   **payload**
   ```json
   {
     "sub": "Joe"
   }
   ```

   In this case, the `header` indicates that the `HS256` (HMAC using SHA-256) algorithm will be used to cryptographically sign 
   the JWT. Also, the `payload` JSON object has a single claim, `sub` with value `Joe`.
   
   There are a number of standard claims, called [Registered Claims](https://tools.ietf.org/html/rfc7519#section-4.1),
   in the specification and `sub` (for 'Subject') is one of them.

2. Remove all unnecessary whitespace in both JSON objects:

   ```groovy
   String header = '{"alg":"HS256"}'
   String claims = '{"sub":"Joe"}'
   ```

3. Get their UTF-8 bytes and Base64URL-encode each:

   ```groovy
   String encodedHeader = base64URLEncode( header.getBytes("UTF-8") )
   String encodedClaims = base64URLEncode( claims.getBytes("UTF-8") )
   ```

4. Concatenate the encoded header and claims with a period character '.' delimiter:

   ```groovy
   String concatenated = encodedHeader + '.' + encodedClaims
   ```

5. Use a sufficiently-strong cryptographic secret or private key, along with a signing algorithm of your choice
    (we'll use HMAC-SHA-256 here), and sign the concatenated string:

    ```groovy
    SecretKey key = getMySecretKey()
    byte[] signature = hmacSha256( concatenated, key )
    ```

6. Because signatures are always byte arrays, Base64URL-encode the signature and join it to the `concatenated` string
   with a period character '.' delimiter:

   ```groovy
   String compact = concatenated + '.' + base64URLEncode( signature )
   ```

And there you have it, the final `compact` String looks like this:

```
eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJKb2UifQ.1KP0SsvENi7Uz1oQc07aXTL7kpQG5jBNIybqr60AlD4
```

This is called a 'JWS' - short for _signed_ JWT.

Of course, no one would want to do this manually in code, and worse, if you get anything wrong, you could introduce
serious security problems and weaknesses.  As a result, JJWT was created to handle all of this for you: JJWT completely
automates both the creation of JWSs and the parsing and verification of JWSs for you.

<a name="overview-example-jwe"></a>
### JWE Example

So far we have seen an unprotected JWT and a cryptographically signed JWT (called a 'JWS').  One of the things 
that is inherent to both of these two is that all the information within them can be seen by anyone - all the data in 
both the header and the payload is publicly visible.  JWS just ensures the data hasn't been changed by anyone - 
it doesn't prevent anyone from seeing it.  Many times, this is just fine because the data within them is not
sensitive information.

But what if you needed to represent information in a JWT that _is_ considered sensitive information - maybe someone's
postal address or social security number or bank account number?

In these cases, we'd want a fully-encrypted JWT, called a 'JWE' for short.  A JWE uses cryptography to ensure that the
payload remains fully encrypted _and_ authenticated so unauthorized parties cannot see data within, nor change the data
without being detected.  Specifically, the JWE specification requires that 
[Authenticated Encryption with Associated Data](https://en.wikipedia.org/wiki/Authenticated_encryption#Authenticated_encryption_with_associated_data_(AEAD))
algorithms are used to fully encrypt and protect data.

A full overview of AEAD algorithms are out of scope for this documentation, but here's an example of a final compact
JWE that utilizes these algorithms (line breaks are for readability only):

```
eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.
6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ.
AxY8DCtDaGlsbGljb3RoZQ.
KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY.
U0m_YmjN04DJvceFICbCVQ
```

Next we'll cover how to install JJWT in your project, and then we'll see how to use JJWT's nice fluent API instead
of risky string manipulation to quickly and safely build JWTs, JWSs, and JWEs.

<a name="install"></a>
## Installation

Use your favorite Maven-compatible build tool to pull the dependencies from Maven Central.

The dependencies could differ slightly if you are working with a [JDK project](#install-jdk) or an 
[Android project](#install-android).

<a name="install-jdk"></a>
### JDK Projects

If you're building a (non-Android) JDK project, you will want to define the following dependencies:

<a name="install-jdk-maven"></a>
#### Maven

```xml
<dependency>
    <groupId>io.jsonwebtoken</groupId>
    <artifactId>jjwt-api</artifactId>
    <version>JJWT_RELEASE_VERSION</version>
</dependency>
<dependency>
    <groupId>io.jsonwebtoken</groupId>
    <artifactId>jjwt-impl</artifactId>
    <version>JJWT_RELEASE_VERSION</version>
    <scope>runtime</scope>
</dependency>
<dependency>
    <groupId>io.jsonwebtoken</groupId>
    <artifactId>jjwt-jackson</artifactId> <!-- or jjwt-gson if Gson is preferred -->
    <version>JJWT_RELEASE_VERSION</version>
    <scope>runtime</scope>
</dependency>
<!-- Uncomment this next dependency if you are using:
     - JDK 10 or earlier, and you want to use RSASSA-PSS (PS256, PS384, PS512) signature algorithms.  
     - JDK 10 or earlier, and you want to use EdECDH (X25519 or X448) Elliptic Curve Diffie-Hellman encryption.
     - JDK 14 or earlier, and you want to use EdDSA (Ed25519 or Ed448) Elliptic Curve signature algorithms.    
     It is unnecessary for these algorithms on JDK 15 or later.
<dependency>
    <groupId>org.bouncycastle</groupId>
    <artifactId>bcprov-jdk15on</artifactId>
    <version>1.70</version>
    <scope>runtime</scope>
</dependency>
-->

```

<a name="install-jdk-gradle"></a>
#### Gradle

```groovy
dependencies {
    implementation 'io.jsonwebtoken:jjwt-api:JJWT_RELEASE_VERSION'
    runtimeOnly 'io.jsonwebtoken:jjwt-impl:JJWT_RELEASE_VERSION'
    runtimeOnly 'io.jsonwebtoken:jjwt-jackson:JJWT_RELEASE_VERSION' // or 'io.jsonwebtoken:jjwt-gson:JJWT_RELEASE_VERSION' for gson
    /* 
      Uncomment this next dependency if you are using:
       - JDK 10 or earlier, and you want to use RSASSA-PSS (PS256, PS384, PS512) signature algorithms.
       - JDK 10 or earlier, and you want to use EdECDH (X25519 or X448) Elliptic Curve Diffie-Hellman encryption.
       - JDK 14 or earlier, and you want to use EdDSA (Ed25519 or Ed448) Elliptic Curve signature algorithms.
      It is unnecessary for these algorithms on JDK 15 or later.
    */
    // runtimeOnly 'org.bouncycastle:bcprov-jdk15on:1.70'
}
```

<a name="install-android"></a>
### Android Projects

Android projects will want to define the following dependencies and Proguard exclusions, and optional
BouncyCastle `Provider`:

<a name="install-android-dependencies"></a>
#### Dependencies

Add the dependencies to your project:

```groovy
dependencies {
    api('io.jsonwebtoken:jjwt-api:JJWT_RELEASE_VERSION')
    runtimeOnly('io.jsonwebtoken:jjwt-impl:JJWT_RELEASE_VERSION') 
    runtimeOnly('io.jsonwebtoken:jjwt-orgjson:JJWT_RELEASE_VERSION') {
        exclude(group: 'org.json', module: 'json') //provided by Android natively
    }
    /* 
      Uncomment this next dependency if you want to use:
       - RSASSA-PSS (PS256, PS384, PS512) signature algorithms.
       - EdECDH (X25519 or X448) Elliptic Curve Diffie-Hellman encryption.
       - EdDSA (Ed25519 or Ed448) Elliptic Curve signature algorithms.
      ** AND ALSO ensure you enable the BouncyCastle provider as shown below **
    */
    //implementation('org.bouncycastle:bcprov-jdk15on:1.70')
}
```

<a name="install-android-proguard"></a>
#### Proguard

You can use the following [Android Proguard](https://developer.android.com/studio/build/shrink-code) exclusion rules: 

```
-keepattributes InnerClasses

-keep class io.jsonwebtoken.** { *; }
-keepnames class io.jsonwebtoken.* { *; }
-keepnames interface io.jsonwebtoken.* { *; }

-keep class org.bouncycastle.** { *; }
-keepnames class org.bouncycastle.** { *; }
-dontwarn org.bouncycastle.**
```

<a name="install-android-bc"></a>
#### Bouncy Castle

If you want to use JWT RSASSA-PSS algorithms (i.e. `PS256`, `PS384`, and `PS512`), EdECDH (`X25512` or `X448`) 
Elliptic Curve Diffie-Hellman encryption, EdDSA (`Ed25519` or `Ed448`) signature algorithms, or you just want to 
ensure your Android application is running an updated version of BouncyCastle, you will need to:
1. Uncomment the BouncyCastle dependency as commented above in the [dependencies](#install-android-dependencies) section.
2. Replace the legacy Android custom `BC` provider with the updated one.

Provider registration needs to be done _early_ in the application's lifecycle, preferably in your application's 
main `Activity` class as a static initialization block.  For example:

```kotlin
class MainActivity : AppCompatActivity() {

    companion object {
        init {
            Security.removeProvider("BC") //remove old/legacy Android-provided BC provider
            Security.addProvider(BouncyCastleProvider()) // add 'real'/correct BC provider
        }
    }

    // ... etc ...
}
```

<a name="install-understandingdependencies"></a>
### Understanding JJWT Dependencies

Notice the above JJWT dependency declarations all have only one compile-time dependency and the rest are declared as 
_runtime_ dependencies.

This is because JJWT is designed so you only depend on the APIs that are explicitly designed for you to use in
your applications and all other internal implementation details - that can change without warning - are relegated to
runtime-only dependencies.  This is an extremely important point if you want to ensure stable JJWT usage and
upgrades over time:

> **Warning**
> 
> **JJWT guarantees semantic versioning compatibility for all of its artifacts _except_ the `jjwt-impl` .jar.  No such 
guarantee is made for the `jjwt-impl` .jar and internal changes in that .jar can happen at any time.  Never add the 
`jjwt-impl` .jar to your project with `compile` scope - always declare it with `runtime` scope.**

This is done to benefit you: great care goes into curating the `jjwt-api` .jar and ensuring it contains what you need
and remains backwards compatible as much as is possible so you can depend on that safely with compile scope.  The 
runtime `jjwt-impl` .jar strategy affords the JJWT developers the flexibility to change the internal packages and 
implementations whenever and however necessary.  This helps us implement features, fix bugs, and ship new releases to 
you more quickly and efficiently.

<a name="quickstart"></a>
## Quickstart

Most complexity is hidden behind a convenient and readable builder-based 
[fluent interface](http://en.wikipedia.org/wiki/Fluent_interface), great for relying on IDE auto-completion to write 
code quickly.  Here's an example:

```java
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import java.security.Key;

// We need a signing key, so we'll create one just for this example. Usually
// the key would be read from your application configuration instead.
SecretKey key = Jwts.SIG.HS256.key().build();

String jws = Jwts.builder().subject("Joe").signWith(key).compact();
```

How easy was that!?

In this case, we are:
 
 1. *building* a JWT that will have the 
[registered claim](https://tools.ietf.org/html/rfc7519#section-4.1) `sub` (Subject) set to `Joe`. We are then
 2. *signing* the JWT using a key suitable for the HMAC-SHA-256 algorithm.  Finally, we are
 3. *compacting* it into its final `String` form.  A signed JWT is called a 'JWS'.

The resultant `jws` String looks like this:

```
eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJKb2UifQ.1KP0SsvENi7Uz1oQc07aXTL7kpQG5jBNIybqr60AlD4
```

Now let's verify the JWT (you should always discard JWTs that don't match an expected signature):

```java
assert Jwts.parser().verifyWith(key).build().parseClaimsJws(jws).getPayload().getSubject().equals("Joe");
```

There are two things going on here. The `key` from before is being used to verify the signature of the JWT. If it 
fails to verify the JWT, a `SignatureException` (which extends `JwtException`) is thrown. Assuming the JWT is 
verified, we parse the claims and assert that that subject is set to `Joe`.  You have to love code one-liners 
that pack a punch!

> **Note**
> 
> **Type-safe JWTs:** To get a type-safe `Claims` JWT result, call the `parseClaimsJws` method (since there are many
similar methods available). You will get an `UnsupportedJwtException` if you parse your JWT with wrong method.

But what if parsing or signature validation failed?  You can catch `JwtException` and react accordingly:

```java
try {

    Jwts.parser().verifyWith(key).build().parseClaimsJws(compactJws);

    //OK, we can trust this JWT

} catch (JwtException e) {

    //don't trust the JWT!
}
```

Now that we've had a quickstart 'taste' of how to create and parse JWTs, let's cover JJWT's API in-depth.

<a name="jwt-create"></a>
## Creating a JWT

You create a JWT as follows:

1. Use the `Jwts.builder()` method to create a `JwtBuilder` instance.
2. Optionally set any [`header` parameters](#jwt-header) as desired.
3. Call builder methods to set the payload [content](#jwt-content) or [claims](#jwt-claims).
4. Optionally call `signWith` or `encryptWith` methods if you want to digitally sign or encrypt the JWT.
5. Call the `compact()` method to produce the resulting compact JWT string.

For example:

```java
String jwt = Jwts.builder()                     // (1)
        
    .header()                                   // (2) optional
        .keyId("aKeyId")
        .and()
        
    .subject("Bob")                             // (3) JSON Claims, or
    //.content(aByteArray, "text/plain")        //     any byte[] content, with media type
        
    .signWith(signingKey)                       // (4) if signing, or
    //.encryptWith(key, keyAlg, encryptionAlg)  //     if encrypting
        
    .compact();                                 // (5)
```

* The JWT `payload` may be either `byte[]` content (via `content`) _or_ JSON Claims 
(such as `subject`, `claims`, etc), but not both.
* Either digital signatures (`signWith`) or encryption (`encryptWith`) may be used, but not both.

> **Warning**
> 
> **Unprotected JWTs**: If you do not use the `signWith` or `encryptWith` builder methods, **an Unprotected JWT will be 
> created, which offers no security protection at all**.  If you need security protection, consider either 
> [digitally signing](#jws) or [encrypting](#jwe) the JWT before calling the `compact()` builder method.

<a name="jwt-header"></a><a name="jws-create-header"></a> <!-- legacy anchors for old links -->
### JWT Header

A JWT header is a JSON `Object` that provides metadata about the contents, format, and any cryptographic operations
relevant to the JWT `payload`.  JJWT provides a number of ways of setting the entire header and/or multiple individual
header parameters (name/value pairs).

<a name="jwt-header-builder"></a><a name="jws-create-header-instance"></a> <!-- legacy anchors for old links -->
#### JwtBuilder Header

The easiest and recommended way to set one or more JWT header parameters (name/value pairs) is to use the
`JwtBuilder`'s `header()` builder as desired, and then call its `and()` method to return back
to the `JwtBuilder` for further configuration. For example:

```java
String jwt = Jwts.builder()
        
    .header()                        // <----
        .keyId("aKeyId")
        .x509Url(aUri)
        .add("someName", anyValue)
        .add(mapValues)
        // ... etc ...
        .and()                      // go back to the JwtBuilder
        
    .subject("Joe")                 // resume JwtBuilder calls...
    // ... etc ...    
    .compact();
```

The `JwtBuilder` `header()` builder also supports automatically calculating X.509 thumbprints and other builder-style benefits that
a simple property getter/setter object would not do.

> **Note**
>
> **Automatic Headers**: You do not need to set the `alg`, `enc` or `zip` headers - JJWT will always set them 
> automatically as needed.

<a name="jwt-header-params"></a>
##### Custom Header Parameters
In addition to type-safe builder methods for standard header parameters, `JwtBuilder.header()` can also support 
arbitrary name/value pairs via the `add` method:

```java
Jwts.builder()
        
    .header()
        .add("aHeaderName", aValue)
        // ... etc ...
        .and() // return to the JwtBuilder
   
// ... etc ...
```

<a name="jwt-header-map"></a><a name="jws-create-header-map"></a> <!-- legacy anchors for old links -->
##### Header Parameter Map
The `add` method is also overloaded to support multiple parameters in a `Map`:

```java
Jwts.builder()
        
    .header()
        .add(multipleHeaderParamsMap)
        // ... etc ...
        .and() // return to the JwtBuilder
   
// ... etc ...
```

#### Jwts HeaderBuilder

Using `Jwts.builder().header()` shown above is the preferred way to modify a header when using the `JwtBuilder`.

However, if you would like to create a 'standalone' `Header` outside of the context of using the `JwtBuilder`, you 
can use `Jwts.header()` instead to return an independent `Header` builder.  For example:

```java
Header header = Jwts.header() 

        .keyId("aKeyId")
        .x509Url(aUri)
        .add("someName", anyValue)
        .add(mapValues)
        // ... etc ...
        
        .build()  // <---- not 'and()'
```

There are only two differences between `Jwts.header()` and `Jwts.builder().header()`:
1. `Jwts.header()` builds a 'detached' `Header` that is not associated with any particular JWT, whereas 
   `Jwts.builder().header()` always modifies the header of the immediate JWT being constructed by its parent
   `JwtBuilder`.


2. `Jwts.header()` has a `build()` method to produce an explicit `Header` instance and 
   `Jwts.builder().header()` does not (it has an `and()` method instead) because its parent `JwtBuilder` will implicitly
   create the header instance when necessary.


A standalone header might be useful if you want to aggregate common header parameters in a single 'template'
instance so you don't have to repeat them for each `JwtBuilder` usage.  Then this 'template' `Header` can be used to 
populate `JwtBuilder` usages by just appending it to the `JwtBuilder` header, for example:

```java
// perhaps somewhere in application configuration:
Header commonHeaders = Jwts.header()
    .issuer("My Company")
    // ... etc ...
    .build();

// --------------------------------

// somewhere else during actual Jwt construction:
String jwt = Jwts.builder()

    .header()
        .add(commonHeaders)                   // <----
        .add("specificHeader", specificValue) // jwt-specific headers...
        .and()

    .subject("whatever")
    // ... etc ...
    .compact();
```

<a name="jwt-payload"></a>
### JWT Payload

A JWT `payload` can be anything at all - anything that can be represented as a byte array, such as text, images, 
documents, and more.  But since a JWT `header` is always JSON, it makes sense that the `payload` could also be JSON,
especially for representing identity claims.

As a result, the `JwtBuilder` supports two distinct payload options:

* `content` if you would like the payload to be arbitrary byte array content, or
* `claims` (and supporting helper methods) if you would like the payload to be a JSON Claims `Object`.

Either option may be used, but not both. Using both will cause `compact()` to throw an exception.

<a name="jwt-content"></a>
#### Arbitrary Content

You can set the JWT payload to be any arbitrary byte array content by using the `JwtBuilder` `content` method.
For example:

```java
byte[] content = "Hello World".getBytes(StandardCharsets.UTF_8);

String jwt = Jwts.builder()

    .content(content, "text/plain") // <---
    
    // ... etc ...
        
    .build();
```

Notice this particular example of `content` uses the two-argument convenience variant:
1. The first argument is the actual byte content to set as the JWT payload
2. The second argument is a String identifier of an IANA Media Type.

The second argument will cause the `JwtBuilder` to automatically set the `cty` (Content Type) header according to the
JWT specification's [recommended compact format](https://www.rfc-editor.org/rfc/rfc7515.html#section-4.1.10).

This two-argument variant is typically recommended over the single-argument `content(byte[])` method because it
guarantees the JWT recipient can inspect the `cty` header to determine how to convert the `payload` byte array into
a final form that the application can use.

Without setting the `cty` header, the JWT recipient _must_ know via out-of-band (external) information how to process
the byte array, which is usually less convenient and always requires code changes if the content format ever changes.
For these reasons, it is strongly recommended to use the two-argument `content` method variant.

<a name="jwt-claims"></a><a name="jws-create-claims"></a> <!-- legacy anchors for old links -->
#### JWT Claims

Instead of a content byte array, a JWT payload may contain assertions or claims for a JWT recipient. In 
this case, the payload is a `Claims` JSON `Object`, and JJWT supports claims creation with type-safe 
builder methods.

<a name="jwt-claims-standard"></a><a name="jws-create-claims-standard"></a> <!-- legacy anchors for old links -->
##### Standard Claims

The `JwtBuilder` provides convenient builder methods for standard registered Claim names defined in the JWT
specification.  They are:

* `issuer`: sets the [`iss` (Issuer) Claim](https://tools.ietf.org/html/rfc7519#section-4.1.1)
* `subject`: sets the [`sub` (Subject) Claim](https://tools.ietf.org/html/rfc7519#section-4.1.2)
* `audience`: sets the [`aud` (Audience) Claim](https://tools.ietf.org/html/rfc7519#section-4.1.3)
* `expiration`: sets the [`exp` (Expiration Time) Claim](https://tools.ietf.org/html/rfc7519#section-4.1.4)
* `notBefore`: sets the [`nbf` (Not Before) Claim](https://tools.ietf.org/html/rfc7519#section-4.1.5)
* `issuedAt`: sets the [`iat` (Issued At) Claim](https://tools.ietf.org/html/rfc7519#section-4.1.6)
* `id`: sets the [`jti` (JWT ID) Claim](https://tools.ietf.org/html/rfc7519#section-4.1.7)

For example:

```java

String jws = Jwts.builder()

    .issuer("me")
    .subject("Bob")
    .audience("you")
    .expiration(expiration) //a java.util.Date
    .notBefore(notBefore) //a java.util.Date 
    .issuedAt(new Date()) // for example, now
    .id(UUID.randomUUID().toString()) //just an example id
    
    /// ... etc ...
```

<a name="jwt-claims-custom"></a><a name="jws-create-claims-custom"></a> <!-- legacy anchors for old links -->
##### Custom Claims

If you need to set one or more custom claims that don't match the standard setter method claims shown above, you
can simply call the `JwtBuilder` `claim` method one or more times as needed:

```java
String jws = Jwts.builder()

    .claim("hello", "world")
    
    // ... etc ...
```

Each time `claim` is called, it simply appends the key-value pair to an internal `Claims` builder, potentially
overwriting any existing identically-named key/value pair.

Obviously, you do not need to call `claim` for any [standard claim name](#jws-create-claims-standard), and it is
recommended instead to call the standard respective type-safe named builder method as this enhances readability.

<a name="jws-create-claims-instance"></a> <!-- legacy anchors for old links -->
<a name="jwt-claims-instance"></a>
<a name="jwt-claims-map"></a><a name="jws-create-claims-map"></a> <!-- legacy anchors for old links -->
##### Claims Map

If you want to add multiple claims at once, you can use `JwtBuilder` `claims(Map)` method:

```java

Map<String,?> claims = getMyClaimsMap(); //implement me

String jws = Jwts.builder()

    .claims(claims)
    
    // ... etc ...
```

<a name="jwt-compression"></a><a name="jws-create-compression"></a> <!-- legacy anchors for old links -->
### JWT Compression

If your JWT payload is large (contains a lot of data), you might want to compress the JWT to reduce its size.  Note 
that this is *not* a standard feature for all JWTs - only JWEs - and is not likely to be supported by other JWT 
libraries for non-JWE tokens.  JJWT supports compression for both JWSs and JWEs, however.

Please see the main [Compression](#compression) section to see how to compress and decompress JWTs.

<a name="jwt-read"></a>
## Reading a JWT

You read (parse) a JWT as follows:

1. Use the `Jwts.parser()` method to create a `JwtParserBuilder` instance.
2. Optionally call `keyLocator`, `verifyWith` or `decryptWith` methods if you expect to parse [signed](#jws) or [encrypted](#jwe) JWTs.
3. Call the `build()` method on the `JwtParserBuilder` to create and return a thread-safe `JwtParser`.
4. Call one of the various `parse*` methods with your compact JWT string, depending on the type of JWT you expect.
5. Wrap the `parse*` call in a try/catch block in case parsing, signature verification, or decryption fails.

For example:

```java
Jwt<?,?> jwt;

try {
    jwt = Jwts.parser()     // (1)
        
    .keyLocator(keyLocator) // (2) dynamically locate signing or encryption keys    
    //.verifyWith(key)      //     or a static key used to verify all signed JWTs
    //.decryptWith(key)     //     or a static key used to decrypt all encrypted JWTs
        
    .build()                // (3)
        
    .parse(compact);        // (4) or parseClaimsJws, parseClaimsJwe, parseContentJws, etc
    
    // we can safely trust the JWT
     
catch (JwtException ex) {   // (5)
    
    // we *cannot* use the JWT as intended by its creator
}
```

> **Note**
> 
> **Type-safe JWTs:** If you are certain your parser will only ever encounter a specific kind of JWT (for example, you only 
> ever use signed JWTs with `Claims` payloads, or encrypted JWTs with `byte[]` content payloads, etc), you can call the 
> associated type-safe `parseClaimsJws`, `parseClaimsJwe`, (etc) method variant instead of the generic `parse` method. 
> 
> These `parse*` methods will return the type-safe JWT you are expecting, for example, a `Jws<Claims>` or `Jwe<byte[]>` 
> instead of a generic `Jwt<?,?>` instance.

<a name="jwt-read-key"></a>
### Static Parsing Key

If the JWT parsed is a JWS or JWE, a key will be necessary to verify the signature or decrypt it.  If a JWS and 
signature verification fails, or if a JWE and decryption fails, the JWT cannot be safely trusted and should be 
discarded. 

So which key do we use?

* If parsing a JWS and the JWS was signed with a `SecretKey`, the same `SecretKey` should be specified on the 
  `JwtParserBuilder`.  For example:

  ```java
  Jwts.parser()
      
    .verifyWith(secretKey) // <----
    
    .build()
    .parseClaimsJws(jwsString);
  ```
* If parsing a JWS and the JWS was signed with a `PrivateKey`, that key's corresponding `PublicKey` (not the 
  `PrivateKey`) should be specified on the `JwtParserBuilder`.  For example:

  ```java
  Jwts.parser()
      
    .verifyWith(publicKey) // <---- publicKey, not privateKey
    
    .build()
    .parseClaimsJws(jwsString);
  ```
* If parsing a JWE and the JWE was encrypted with direct encryption using a `SecretKey`, the same `SecretKey` should be 
  specified on the `JwtParserBuilder`. For example:

  ```java
  Jwts.parser()
      
    .decryptWith(secretKey) // <---- or a Password from Keys.password(charArray)
    
    .build()
    .parseClaimsJwe(jweString);
  ```
* If parsing a JWE and the JWE was encrypted with a key algorithm using with a `PublicKey`, that key's corresponding 
  `PrivateKey` (not the `PublicKey`) should be specified on the `JwtParserBuilder`.  For example:

  ```java
  Jwts.parser()
      
    .decryptWith(privateKey) // <---- privateKey, not publicKey
    
    .build()
    .parseClaimsJwe(jweString);
  ```
  
#### Multiple Keys?

But you might have noticed something - what if your application doesn't use just a single `SecretKey` or `KeyPair`? What
if JWSs and JWEs can be created with different `SecretKey`s or public/private keys, or a combination of both?  How do
you know which key to specify if you don't inspect the JWT first?

In these cases, you can't call the `JwtParserBuilder`'s `verifyWith` or `decryptWith` methods with a single key -
instead, you'll need to configure a parsing Key Locator, discussed next.

<a name="key-locator"></a>
### Dynamic Key Lookup

It is common in many applications to receive JWTs that can be encrypted or signed by different cryptographic keys.  For
example, maybe a JWT created to assert a specific user identity uses a Key specific to that exact user. Or perhaps JWTs
specific to a particular customer all use that customer's Key.  Or maybe your application creates JWTs that are
encrypted with a key specific to your application for your own use (e.g. a user session token).

In all of these and similar scenarios, you won't know which key was used to sign or encrypt a JWT until the JWT is
received, at parse time, so you can't 'hard code' any verification or decryption key using the `JwtParserBuilder`'s
`verifyWith` or `decryptWith` methods.  Those are only to be used when the same key is used to verify or decrypt
*all* JWSs or JWEs, which won't work for dynamically signed or encrypted JWTs.

<a name="key-locator-custom"></a>
#### Key Locator

If you need to support dynamic key lookup when encountering JWTs, you'll need to implement
the `Locator<Key>` interface and specify an instance on the `JwtParserBuilder` via the `keyLocator` method. For
example:

```java
Locator<Key> keyLocator = getMyKeyLocator();

Jwts.parser()

    .keyLocator(keyLocator) // <----
    
    .build()
    // ... etc ...
```

A `Locator<Key>` is used to lookup _both_ JWS signature verification keys _and_ JWE decryption keys.  You need to
determine which key to return based on information in the JWT `header`, for example:

```java
public class MyKeyLocator extends LocatorAdapter<Key> {
    
    @Override
    public Key locate(ProtectedHeader<?> header) { // a JwsHeader or JweHeader
        // implement me
    }
}
```

The `JwtParser` will invoke the `locate` method after parsing the JWT `header`, but _before parsing the `payload`,
or verifying any JWS signature or decrypting any JWE ciphertext_. This allows you to inspect the `header` argument
for any information that can help you look up the `Key` to use for verifying _that specific jwt_.  This is very
powerful for applications with more complex security models that might use different keys at different times or for
different users or customers.

<a name="key-locator-strategy"></a>
#### Key Locator Strategy

What data might you inspect to determine how to lookup a signature verification or decryption key?

The JWT specifications' preferred approach is to set a `kid` (Key ID) header value when the JWT is being created,
for example:

```java
Key key = getSigningKey(); // or getEncryptionKey() for JWE

String keyId = getKeyId(key); //any mechanism you have to associate a key with an ID is fine

String jws = Jwts.builder()
        
    .header().keyId(keyId).and()               // <--- add `kid` header
    
    .signWith(key)                             // for JWS
    //.encryptWith(key, keyAlg, encryptionAlg) // for JWE
    .compact();
```

Then during parsing, your `Locator<Key>` implementation can inspect the `header` to get the `kid` value and then use it
to look up the verification or decryption key from somewhere, like a database, keystore or Hardware Security Module
(HSM).  For example:

```java
public class MyKeyLocator extends LocatorAdapter<Key> {
    
    @Override
    public Key locate(ProtectedHeader<?> header) { // both JwsHeader and JweHeader extend ProtectedHeader
        
        //inspect the header, lookup and return the verification key
        String keyId = header.getKeyId(); //or any other field that you need to inspect

        Key key = lookupKey(keyId); //implement me

        return key;
    }
}
```

Note that inspecting the `header.getKeyId()` is just the most common approach to look up a key - you could
inspect any number of header fields to determine how to lookup the verification or decryption key.  It is all based on
how the JWT was created.

If you extend `LocatorAdapter<Key>` as shown above, but for some reason have different lookup strategies for
signature verification keys versus decryption keys, you can forego overriding the `locate(ProtectedHeader<?>)` method
in favor of two respective `locate(JwsHeader)` and `locate(JweHeader)` methods:

```java
public class MyKeyLocator extends LocatorAdapter<Key> {
    
    @Override
    public Key locate(JwsHeader header) {
        String keyId = header.getKeyId(); //or any other field that you need to inspect
        return lookupSignatureVerificationKey(keyId); //implement me
    }
    
    @Override
    public Key locate(JweHeader header) {
        String keyId = header.getKeyId(); //or any other field that you need to inspect
        return lookupDecryptionKey(keyId); //implement me
    }
}
```
> **Note**
>
> **Simpler Lookup**: If possible, try to keep the key lookup strategy the same between JWSs and JWEs (i.e. using
> only `locate(ProtectedHeader<?>)`), preferably using only
> the `kid` (Key ID) header value or perhaps a public key thumbprint.  You will find the implementation is much
> simpler and easier to maintain over time, and also creates smaller headers for compact transmission.

<a name="key-locator-retvals"></a>
#### Key Locator Return Values

Regardless of which implementation strategy you choose, remember to return the appropriate type of key depending
on the type of JWS or JWE algorithm used.  That is:

* For JWS:
    * For HMAC-based signature algorithms, the returned verification key should be a `SecretKey`, and,
    * For asymmetric signature algorithms, the returned verification key should be a `PublicKey` (not a `PrivateKey`).
* For JWE:
    * For JWE direct encryption, the returned decryption key should be a `SecretKey`.
    * For password-based key derivation algorithms, the returned decryption key should be a 
      `io.jsonwebtoken.security.Password`.  You can create a `Password` instance by calling 
      `Keys.password(char[] passwordCharacters)`.
    * For asymmetric key management algorithms, the returned decryption key should be a `PrivateKey` (not a `PublicKey`).

<a name="jwt-read-claims"></a><a name="jws-read-claims"></a> <!-- legacy anchor for old links -->
### Claim Assertions

You can enforce that the JWT you are parsing conforms to expectations that you require and are important for your
application.

For example, let's say that you require that the JWT you are parsing has a specific `sub` (subject) value,
otherwise you may not trust the token.  You can do that by using one of the various `require`* methods on the
`JwtParserBuilder`:

```java
try {
    Jwts.parser().requireSubject("jsmith")/* etc... */.build().parse(s);
} catch (InvalidClaimException ice) {
    // the sub field was missing or did not have a 'jsmith' value
}
```

If it is important to react to a missing vs an incorrect value, instead of catching `InvalidClaimException`,
you can catch either `MissingClaimException` or `IncorrectClaimException`:

```java
try {
    Jwts.parser().requireSubject("jsmith")/* etc... */.build().parse(s);
} catch(MissingClaimException mce) {
    // the parsed JWT did not have the sub field
} catch(IncorrectClaimException ice) {
    // the parsed JWT had a sub field, but its value was not equal to 'jsmith'
}
```

You can also require custom fields by using the `require(fieldName, requiredFieldValue)` method - for example:

```java
try {
    Jwts.parser().require("myfield", "myRequiredValue")/* etc... */.build().parse(s);
} catch(InvalidClaimException ice) {
    // the 'myfield' field was missing or did not have a 'myRequiredValue' value
}
```
(or, again, you could catch either `MissingClaimException` or `IncorrectClaimException` instead).

Please see the `JwtParserBuilder` class and/or JavaDoc for a full list of the various `require`* methods you may use 
for claims assertions.

<a name="jwt-read-clock"></a><a name="jws-read-clock"></a> <!-- legacy anchor for old links -->
### Accounting for Clock Skew

When parsing a JWT, you might find that `exp` or `nbf` claim assertions fail (throw exceptions) because the clock on
the parsing machine is not perfectly in sync with the clock on the machine that created the JWT.  This can cause
obvious problems since `exp` and `nbf` are time-based assertions, and clock times need to be reliably in sync for shared
assertions.

You can account for these differences (usually no more than a few minutes) when parsing using the `JwtParserBuilder`'s
`clockSkewSeconds`. For example:

```java
long seconds = 3 * 60; //3 minutes

Jwts.parser()
    
    .clockSkewSeconds(seconds) // <----
    
    // ... etc ...
    .build()
    .parse(jwt);
```
This ensures that minor clock differences between the machines can be ignored. Two or three minutes should be more than
enough; it would be fairly strange if a production machine's clock was more than 5 minutes difference from most
atomic clocks around the world.

<a name="jwt-read-clock-custom"></a><a name="jws-read-clock-custom"></a> <!-- legacy anchor for old links -->
#### Custom Clock Support

If the above `clockSkewSeconds` isn't sufficient for your needs, the timestamps created
during parsing for timestamp comparisons can be obtained via a custom time source.  Call the `JwtParserBuilder`'s 
`clock` method with an implementation of the `io.jsonwebtoken.Clock` interface.  For example:

 ```java
Clock clock = new MyClock();

Jwts.parser().clock(myClock) //... etc ...
``` 

The `JwtParser`'s default `Clock` implementation simply returns `new Date()` to reflect the time when parsing occurs,
as most would expect.  However, supplying your own clock could be useful, especially when writing test cases to
guarantee deterministic behavior.

<a name="jwt-read-decompression"></a>
### JWT Decompression

If you used JJWT to compress a JWT and you used a custom compression algorithm, you will need to tell the
`JwtParserBuilder` how to resolve your `CompressionCodec` to decompress the JWT.

Please see the [Compression](#compression) section below to see how to decompress JWTs during parsing.

<a name="jws"></a>
## Signed JWTs

The JWT specification provides for the ability to 
[cryptographically _sign_](https://en.wikipedia.org/wiki/Digital_signature) a JWT.  Signing a JWT:
 
1. guarantees the JWT was created by someone we know (it is authentic) as well as
2. guarantees that no-one has manipulated or changed the JWT after it was created (its integrity is maintained).

These two properties - authenticity and integrity - assure us that a JWT contains information we can trust.  If a 
JWT fails authenticity or integrity checks, we should always reject that JWT because we can't trust it.

But before we dig in to showing you how to create a JWS using JJWT, let's briefly discuss Signature Algorithms and 
Keys, specifically as they relate to the JWT specifications.  Understanding them is critical to being able to create a 
JWS properly.

<a name="jws-alg"></a>
### Standard Signature Algorithms

The JWT specifications identify 13 standard signature algorithms - 3 secret key algorithms and 10 asymmetric
key algorithms:

| Identifier | Signature Algorithm |
| --- | --- |
| `HS256` | HMAC using SHA-256 |
| `HS384` | HMAC using SHA-384 |
| `HS512` | HMAC using SHA-512 |
| `ES256` | ECDSA using P-256 and SHA-256 |
| `ES384` | ECDSA using P-384 and SHA-384 |
| `ES512` | ECDSA using P-521 and SHA-512 |
| `RS256` | RSASSA-PKCS-v1_5 using SHA-256 |
| `RS384` | RSASSA-PKCS-v1_5 using SHA-384 |
| `RS512` | RSASSA-PKCS-v1_5 using SHA-512 |
| `PS256` | RSASSA-PSS using SHA-256 and MGF1 with SHA-256<sup><b>1</b></sup> |
| `PS384` | RSASSA-PSS using SHA-384 and MGF1 with SHA-384<sup><b>1</b></sup> |
| `PS512` | RSASSA-PSS using SHA-512 and MGF1 with SHA-512<sup><b>1</b></sup> |
| `EdDSA` | Edwards-Curve Digital Signature Algorithm (EdDSA)<sup><b>2</b></sup> | 

<sup><b>1</b>. Requires Java 11 or a compatible JCA Provider (like BouncyCastle) in the runtime classpath.</sup>

<sup><b>2</b>. Requires Java 15 or a compatible JCA Provider (like BouncyCastle) in the runtime classpath.</sup>

These are all represented as constants in the `io.jsonwebtoken.Jwts.SIG` convenience class.

<a name="jws-key"></a>
### Signature Algorithms Keys

What's really important about the above standard signature algorithms - other than their security properties - is that 
the JWT specification [RFC 7518, Sections 3.2 through 3.5](https://tools.ietf.org/html/rfc7518#section-3)
_requires_ (mandates) that you MUST use keys that are sufficiently strong for a chosen algorithm.

This means that JJWT - a specification-compliant library - will also enforce that you use sufficiently strong keys
for the algorithms you choose.  If you provide a weak key for a given algorithm, JJWT will reject it and throw an
exception.

This is not because we want to make your life difficult, we promise! The reason why the JWT specification, and
consequently JJWT, mandates key lengths is that the security model of a particular algorithm can completely break
down if you don't adhere to the mandatory key properties of the algorithm, effectively having no security at all.  No
one wants completely insecure JWTs, right?  Right!

So what are the key strength requirements?

<a name="jws-key-hmacsha"></a>
#### HMAC-SHA

JWT HMAC-SHA signature algorithms `HS256`, `HS384`, and `HS512` require a secret key that is _at least_ as many bits as
the algorithm's signature (digest) length per [RFC 7512 Section 3.2](https://tools.ietf.org/html/rfc7518#section-3.2). 
This means:

* `HS256` is HMAC-SHA-256, and that produces digests that are 256 bits (32 bytes) long, so `HS256` _requires_ that you
  use a secret key that is at least 32 bytes long.
  
* `HS384` is HMAC-SHA-384, and that produces digests that are 384 bits (48 bytes) long, so `HS384` _requires_ that you
  use a secret key that is at least 48 bytes long. 

* `HS512` is HMAC-SHA-512, and that produces digests that are 512 bits (64 bytes) long, so `HS512` _requires_ that you
  use a secret key that is at least 64 bytes long. 
  
<a name="jws-key-rsa"></a>
#### RSA

JWT RSA signature algorithms `RS256`, `RS384`, `RS512`, `PS256`, `PS384` and `PS512` all require a minimum key length
(aka an RSA modulus bit length) of `2048` bits per RFC 7512 Sections 
[3.3](https://tools.ietf.org/html/rfc7518#section-3.3) and [3.5](https://tools.ietf.org/html/rfc7518#section-3.5). 
Anything smaller than this (such as 1024 bits) will be rejected with an `WeakKeyException`.

That said, in keeping with best practices and increasing key lengths for security longevity, JJWT 
recommends that you use:

* at least 2048 bit keys with `RS256` and `PS256`
* at least 3072 bit keys with `RS384` and `PS384`
* at least 4096 bit keys with `RS512` and `PS512`

These are only JJWT suggestions and not requirements. JJWT only enforces JWT specification requirements and
for any RSA key, the requirement is the RSA key (modulus) length in bits MUST be >= 2048 bits.

<a name="jws-key-ecdsa"></a>
#### Elliptic Curve

JWT Elliptic Curve signature algorithms `ES256`, `ES384`, and `ES512` all require a key length
(aka an Elliptic Curve order bit length) equal to the algorithm signature's individual 
`R` and `S` components per [RFC 7512 Section 3.4](https://tools.ietf.org/html/rfc7518#section-3.4).  This means:

* `ES256` requires that you use a private key that is exactly 256 bits (32 bytes) long.
  
* `ES384` requires that you use a private key that is exactly 384 bits (48 bytes) long.

* `ES512` requires that you use a private key that is exactly 521 bits (65 or 66 bytes) long (depending on format).

<a name="jws-key-eddsa"></a>
#### Edwards Curve

The JWT Edwards Curve signature algorithm `EdDSA` supports two sizes of private and public `EdECKey`s (these types
were introduced in Java 15):

* `Ed25519` algorithm keys must be 256 bits (32 bytes) long and produce signatures 512 bits (64 bytes) long.

* `Ed448` algorithm keys must be 456 bits (57 bytes) long and produce signatures 912 bits (114 bytes) long.

<a name="jws-key-create"></a>
#### Creating Safe Keys

If you don't want to think about bit length requirements or just want to make your life easier, JJWT has
provided convenient builder classes that can generate sufficiently secure keys for any given
JWT signature algorithm you might want to use.

<a name="jws-key-create-secret"></a>
##### Secret Keys

If you want to generate a sufficiently strong `SecretKey` for use with the JWT HMAC-SHA algorithms, use the respective 
algorithm's `key()` builder method:

```java
SecretKey key = Jwts.SIG.HS256.key().build(); //or HS384.key() or HS512.key()
```

Under the hood, JJWT uses the JCA default provider's `KeyGenerator` to create a secure-random key with the correct 
minimum length for the given algorithm.

If you want to specify a specific JCA `Provider` or `SecureRandom` to use during key generation, you may specify those
as builder arguments. For example:

```java
SecretKey key = Jwts.SIG.HS256.key().provider(aProvider).random(aSecureRandom).build();
```

If you need to save this new `SecretKey`, you can Base64 (or Base64URL) encode it:

```java
String secretString = Encoders.BASE64.encode(key.getEncoded());
```

Ensure you save the resulting `secretString` somewhere safe - 
[Base64-encoding is not encryption](#base64-not-encryption), so it's still considered sensitive information. You can 
further encrypt it, etc, before saving to disk (for example).

<a name="jws-key-create-asym"></a>
##### Asymmetric Keys

If you want to generate sufficiently strong Elliptic Curve or RSA asymmetric key pairs for use with JWT ECDSA or RSA
algorithms, use an algorithm's respective `keyPair()` builder method:

```java
KeyPair keyPair = Jwts.SIG.RS256.keyPair().build(); //or RS384, RS512, PS256, etc...
```

Once you've generated a `KeyPair`, you can use the private key (`keyPair.getPrivate()`) to create a JWS and the 
public key (`keyPair.getPublic()`) to parse/verify a JWS.

> **Note**
> 
> **The `PS256`, `PS384`, and `PS512` algorithms require JDK 11 or a compatible JCA Provider
> (like BouncyCastle) in the runtime classpath.**  
> **The `EdDSA` algorithms requires JDK 15 or a compatible JCA Provider (like BouncyCastle) in the runtime classpath.** 
> If you want to use either set of algorithms, and you are on an earlier JDK that does not support them, 
> see the [Installation](#Installation) section to see how to enable BouncyCastle.  All other algorithms are 
> natively supported by the JDK.

<a name="jws-create"></a>
### Creating a JWS

You create a JWS as follows:

1. Use the `Jwts.builder()` method to create a `JwtBuilder` instance.  
2. Call `JwtBuilder` methods to set the `payload` content or claims and any header parameters as desired.
3. Specify the `SecretKey` or asymmetric `PrivateKey` you want to use to sign the JWT.
4. Finally, call the `compact()` method to compact and sign, producing the final jws.

For example:

```java
String jws = Jwts.builder() // (1)

    .subject("Bob")         // (2) 

    .signWith(key)          // (3) <---
     
    .compact();             // (4)
```

<a name="jws-create-key"></a>
#### Signing Key

It is usually recommended to specify the signing key by calling the `JwtBuilder`'s `signWith` method and let JJWT
determine the most secure algorithm allowed for the specified key.:

```java
String jws = Jwts.builder()

   // ... etc ...
   
   .signWith(key) // <---
   
   .compact();
```

For example, if you call `signWith` with a `SecretKey` that is 256 bits (32 bytes) long, it is not strong enough for
`HS384` or `HS512`, so JJWT will automatically sign the JWT using `HS256`.

When using `signWith` JJWT will also automatically set the required `alg` header with the associated algorithm 
identifier.

Similarly, if you called `signWith` with an RSA `PrivateKey` that was 4096 bits long, JJWT will use the `RS512`
algorithm and automatically set the `alg` header to `RS512`.

The same selection logic applies for Elliptic Curve `PrivateKey`s.

> **Note**
> 
> **You cannot sign JWTs with `PublicKey`s as this is always insecure.** JJWT will reject any specified
> `PublicKey` for signing with an `InvalidKeyException`.

<a name="jws-create-key-secret"></a>
##### SecretKey Formats

If you want to sign a JWS using HMAC-SHA algorithms, and you have a secret key `String` or 
[encoded byte array](https://docs.oracle.com/javase/8/docs/api/java/security/Key.html#getEncoded--), you will need
to convert it into a `SecretKey` instance to use as the `signWith` method argument.

If your secret key is:

* An [encoded byte array](https://docs.oracle.com/javase/8/docs/api/java/security/Key.html#getEncoded--):
  ```java
  SecretKey key = Keys.hmacShaKeyFor(encodedKeyBytes);
  ```
* A Base64-encoded string:
  ```java
  SecretKey key = Keys.hmacShaKeyFor(Decoders.BASE64.decode(secretString));
  ```
* A Base64URL-encoded string:
  ```java
  SecretKey key = Keys.hmacShaKeyFor(Decoders.BASE64URL.decode(secretString));
  ```
* A raw (non-encoded) string (e.g. a password String):
  ```java
  SecretKey key = Keys.hmacShaKeyFor(secretString.getBytes(StandardCharsets.UTF_8));
  ```
  It is always incorrect to call `secretString.getBytes()` (without providing a charset).
  
  However, raw password strings like this, e.g. `correcthorsebatterystaple` should be avoided whenever possible 
  because they can inevitably result in weak or susceptible keys. Secure-random keys are almost always stronger. 
  If you are able, prefer creating a [new secure-random secret key](#jws-key-create-secret) instead.

<a name="jws-create-key-algoverride"></a>
##### SignatureAlgorithm Override

In some specific cases, you might want to override JJWT's default selected signature algorithm for a given key.

For example, if you have an RSA `PrivateKey` that is 2048 bits, JJWT would automatically choose the `RS256` algorithm.
If you wanted to use `RS384` or `RS512` instead, you could manually specify it with the overloaded `signWith` method
that accepts the `SignatureAlgorithm` as an additional parameter:

```java

   .signWith(privateKey, Jwts.SIG.RS512) // <---
   
   .compact();

```

This is allowed because the JWT specification allows any RSA algorithm strength for any RSA key >= 2048 bits.  JJWT just
prefers `RS512` for keys >= 4096 bits, followed by `RS384` for keys >= 3072 bits and finally `RS256` for keys >= 2048
bits.

**In all cases however, regardless of your chosen algorithms, JJWT will assert that the specified key is allowed to be 
used for that algorithm when possible according to the JWT specification requirements.**

<a name="jws-create-compression"></a>
#### JWS Compression

If your JWT payload is large (contains a lot of data), and you are certain that JJWT will also be the same library 
that reads/parses your JWS, you might want to compress the JWS to reduce its size.  

> **Warning**
> 
> **Not Standard for JWS**: JJWT supports compression for JWS, but it is not a standard feature for JWS.  The
> JWT RFC specifications standardize this _only_ for JWEs, and it is not likely to be supported by other JWT libraries
> for JWS.  Use JWS compression only if you are certain that JJWT (or another library that supports JWS compression) 
> will be parsing the JWS

Please see the main [Compression](#compression) section to see how to compress and decompress JWTs.

<a name="jws-read"></a>
### Reading a JWS

You read (parse) a JWS as follows:

1. Use the `Jwts.parser()` method to create a `JwtParserBuilder` instance.
2. Call either [keyLocator](#key-locator) or `verifyWith` methods to determine the key used to verify the JWS signature.
3. Call the `build()` method on the `JwtParserBuilder` to return a thread-safe `JwtParser`.
4. Finally, call the `parseClaimsJws(String)` method with your jws `String`, producing the original JWS.
5. The entire call is wrapped in a try/catch block in case parsing or signature validation fails.  We'll cover
   exceptions and causes for failure later.

For example:

```java
Jws<Claims> jws;

try {
    jws = Jwts.parser()         // (1)
        
    .keyLocator(keyLocator)     // (2) dynamically lookup verification keys based on each JWS    
    //.verifyWith(key)          //     or a static key used to verify all encountered JWSs
        
    .build()                    // (3)
    .parseClaimsJws(jwsString); // (4) or parseContentJws(jwsString)
    
    // we can safely trust the JWT
     
catch (JwtException ex) {       // (5)
    
    // we *cannot* use the JWT as intended by its creator
}
```

> **Note**
>
> **Type-safe JWSs:**
> * If you are expecting a JWS with a Claims `payload`, call the `JwtParser`'s `parseClaimsJws` method.
> * If you are expecting a JWS with a content `payload`, call the `JwtParser`'s `parseContentJws` method.

<a name="jws-read-key"></a>
#### Verification Key

The most important thing to do when reading a JWS is to specify the key used to verify the JWS's
cryptographic signature.  If signature verification fails, the JWT cannot be safely trusted and should be 
discarded.

So which key do we use for verification?

* If the jws was signed with a `SecretKey`, the same `SecretKey` should be specified on the `JwtParserBuilder`.  
For example:

  ```java
  Jwts.parser()
      
    .verifyWith(secretKey) // <----
    
    .build()
    .parseClaimsJws(jwsString);
  ```
* If the jws was signed with a `PrivateKey`, that key's corresponding `PublicKey` (not the `PrivateKey`) should be 
  specified on the `JwtParserBuilder`.  For example:

  ```java
  Jwts.parser()
      
    .verifyWith(publicKey) // <---- publicKey, not privateKey
    
    .build()
    .parseClaimsJws(jwsString);
  ```

<a name="jws-read-key-locator"></a><a name="jws-read-key-resolver"></a> <!-- legacy anchors for old links -->
#### Verification Key Locator
  
But you might have noticed something - what if your application doesn't use just a single `SecretKey` or `KeyPair`? What
if JWSs can be created with different `SecretKey`s or public/private keys, or a combination of both?  How do you
know which key to specify if you can't inspect the JWT first?

In these cases, you can't call the `JwtParserBuilder`'s `verifyWith` method with a single key - instead, you'll need a
Key Locator.  Please see the [Key Lookup](#key-locator) section to see how to dynamically obtain different keys when
parsing JWSs or JWEs.

<a name="jws-read-decompression"></a>
#### JWS Decompression

If you used JJWT to compress a JWS and you used a custom compression algorithm, you will need to tell the 
`JwtParserBuilder` how to resolve your `CompressionCodec` to decompress the JWT.

Please see the [Compression](#compression) section below to see how to decompress JWTs during parsing.

<a name="jwe"></a>
## Encrypted JWTs

The JWT specification also provides for the ability to encrypt and decrypt a JWT.  Encrypting a JWT:

1. guarantees that no-one other than the intended JWT recipient can see the JWT `payload` (it is confidential), and 
2. guarantees that no-one has manipulated or changed the JWT after it was created (its integrity is maintained).

These two properties - confidentiality and integrity - assure us that an encrypted JWT contains a `payload` that 
no-one else can see, _nor_ has anyone changed or altered the data in transit.

Encryption and confidentiality seem somewhat obvious: if you encrypt a message, it is confidential by the notion that
random 3rd parties cannot make sense of the encrypted message. But some might be surprised to know that **_general 
encryption does _not_ guarantee that someone hasn't tampered/altered an encrypted message in transit_**.  Most of us 
assume that if a message can be decrypted, then the message would be authentic and unchanged - after all, if you can 
decrypt it, it must not have been tampered with, right? Because if it was changed, decryption would surely fail, right?

Unfortunately, this is not actually guaranteed in all cryptographic ciphers. There are certain attack vectors where 
it is possible to change an encrypted payload (called 'ciphertext'), and the message recipient is still able to 
successfully decrypt the (modified) payload.  In these cases, the ciphertext integrity was not maintained - a 
malicious 3rd party could intercept a message and change the payload content, even if they don't understand what is 
inside the payload, and the message recipient could never know.

To combat this, there is a category of encryption algorithms that ensures                                                                                 both confidentiality _and_ integrity of the 
ciphertext data.  These types of algorithms are called 
[Authenticated Encryption](https://en.wikipedia.org/wiki/Authenticated_encryption) algorithms.

As a result, to ensure JWTs do not suffer from this problem, the JWE RFC specifications require that any encryption
algorithm used to encrypt a JWT _MUST_ be an Authenticated Encryption algorithm.  JWT users can be sufficiently 
confident their encrypted JWTs maintain the properties of both confidentiality and integrity.

<a name="jwe-enc"></a>
### JWE Encryption Algorithms

The JWT specification defines 6 standard Authenticated Encryption algorithms used to encrypt a JWT `payload`:

| Identifier                       | Required Key Bit Length | Encryption Algorithm |
|--------------------------------- | ----------------------- | -------------------- |
| <code>A128CBC&#8209;HS256</code> | 256 | [AES_128_CBC_HMAC_SHA_256](https://www.rfc-editor.org/rfc/rfc7518.html#section-5.2.3) authenticated encryption algorithm |
| `A192CBC-HS384`                  | 384 | [AES_192_CBC_HMAC_SHA_384](https://www.rfc-editor.org/rfc/rfc7518.html#section-5.2.4) authenticated encryption algorithm |
| `A256CBC-HS512`                  | 512 | [AES_256_CBC_HMAC_SHA_512](https://www.rfc-editor.org/rfc/rfc7518.html#section-5.2.5) authenticated encryption algorithm |
| `A128GCM`                        | 128 | AES GCM using 128-bit key<sup><b>1</b></sup> |
| `A192GCM`                        | 192 | AES GCM using 192-bit key<sup><b>1</b></sup> |
| `A256GCM`                        | 256 | AES GCM using 256-bit key<sup><b>1</b></sup> |

<sup><b>1. </b>Requires Java 8+ or a compatible JCA Provider (like BouncyCastle) in the runtime classpath.</sup>

These are all represented as constants in the `io.jsonwebtoken.Jwts.ENC` registry singleton as 
implementations of the `io.jsonwebtoken.security.AeadAlgorithm` interface.

As shown in the table above, each algorithm requires a key of sufficient length.  The JWT specification
[RFC 7518, Sections 5.2.3 through 5.3](https://www.rfc-editor.org/rfc/rfc7518.html#section-5.2.3)
_requires_ (mandates) that you MUST use keys that are sufficiently strong for a chosen algorithm.  This means that 
JJWT - a specification-compliant library - will also enforce that you use sufficiently strong keys
for the algorithms you choose.  If you provide a weak key for a given algorithm, JJWT will reject it and throw an
exception.

The reason why the JWT specification, and consequently JJWT, mandates key lengths is that the security model of a 
particular algorithm can completely break down if you don't adhere to the mandatory key properties of the algorithm, 
effectively having no security at all.

<a name="jwe-enc-symmetric"></a>
#### Symmetric Ciphers

You might have noticed something about the above Authenticated Encryption algorithms: they're all variants of the 
AES algorithm, and AES always uses a symmetric (secret) key to perform encryption and decryption.  That's kind of 
strange, isn't it?

What about RSA and Elliptic Curve asymmetric key cryptography? And Diffie-Hellman key exchange?  What about 
password-based key derivation algorithms? Surely any of those could be desirable depending on the use case, no?

Yes, they definitely can, and the JWT specifications do support them, albeit indirectly:  those other 
algorithms _are_ indeed supported and used, but they aren't used to encrypt the JWT `payload` directly.  They are 
used to _produce_ the actual key used to encrypt the `JWT` payload.

This is all done via the JWT specification's concept of a Key Management Algorithm, covered next.  After we cover that, 
we'll show you how to encrypt and parse your own JWTs with the `JwtBuilder` and `JwtParserBuilder`.

<a name="jwe-alg"></a>
### JWE Key Management Algorithms

As stated above, all standard JWA Encryption Algorithms are AES-based authenticated encryption algorithms.  So what 
about RSA and Elliptic Curve cryptography? And password-based key derivation, or Diffie-Hellman exchange?

All of those are supported as well, but they are not used directly for encryption. They are used to _produce_ the 
key that will be used to directly encrypt the JWT `payload`.

That is, JWT encryption can be thought of as a two-step process, shown in the following pseudocode:

```groovy
Key algorithmKey = getKeyManagementAlgorithmKey(); // PublicKey, SecretKey, or Password

SecretKey contentEncryptionKey = keyManagementAlgorithm.produceEncryptionKey(algorithmKey); // 1

byte[] ciphertext = encryptionAlgorithm.encrypt(payload, contentEncryptionKey);             // 2
```

Steps:

1. Use the `algorithmKey` to produce the actual key that will be used to encrypt the payload.  The JWT specifications
   call this result the 'Content Encryption Key'.
2. Take the resulting Content Encryption Key and use it directly with the Authenticated Encryption algorithm to
   actually encrypt the JWT `payload`.

So why the indirection?  Why not just use any `PublicKey`, `SecretKey` or `Password` to encrypt the `payload`
_directly_ ?

There are quite a few reasons for this.

1. Asymmetric key encryption (like RSA and Elliptic Curve) tends to be slow.  Like _really_ slow.  Symmetric key
   cipher algorithms in contrast are _really fast_.  This matters a lot in production applications that could be 
   handling a JWT on every HTTP request, which could be thousands per second.
2. RSA encryption (for example) can only encrypt a relatively small amount of data. A 2048-bit RSA key can only 
   encrypt up to a maximum of 245 bytes.  A 4096-bit RSA key can only encrypt up to a maximum of 501 bytes.  There are
   plenty of JWTs that can exceed 245 bytes, and that would make RSA unusable.
3. Passwords usually make for very poor encryption keys - they often have poor entropy, or they themselves are
   often too short to be used directly with algorithms that mandate minimum key lengths to help ensure safety.

For these reasons and more, using one secure algorithm to generate or encrypt a key used for another (very fast) secure
algorithm has been proven to be a great way to increase security through many more secure algorithms while 
also still resulting in very fast and secure output.  This is after all how TLS (for https encryption) works - 
two parties can use more complex cryptography (like RSA or Elliptic Curve) to negotiate a small, fast encryption key. 
This fast encryption key is produced during the 'TLS handshake' and is called the TLS 'session key'.

So the JWT specifications work much in the same way: one key from any number of various algorithm types can be used
to produce a final symmetric key, and that symmetric key is used to encrypt the JWT `payload`.

<a name="jwe-alg-standard"></a>
#### JWE Standard Key Management Algorithms

The JWT specification defines 17 standard Key Management Algorithms used to produce the JWE 
Content Encryption Key (CEK):

| Identifier | Key Management Algorithm                                                      |
| --- |-------------------------------------------------------------------------------|   
| `RSA1_5` | RSAES-PKCS1-v1_5                                                              |
| `RSA-OAEP` | RSAES OAEP using default parameters                                           |
| `RSA-OAEP-256` | RSAES OAEP using SHA-256 and MGF1 with SHA-256                                |
| `A128KW` | AES Key Wrap with default initial value using 128-bit key                     |
| `A192KW` | AES Key Wrap with default initial value using 192-bit key                     |
| `A256KW` | AES Key Wrap with default initial value using 256-bit key                     |
| `dir` | Direct use of a shared symmetric key as the Content Encryption Key            |
| `ECDH-ES` | Elliptic Curve Diffie-Hellman Ephemeral Static key agreement using Concat KDF |
| `ECDH-ES+A128KW` | ECDH-ES using Concat KDF and CEK wrapped with "A128KW"                        |
| `ECDH-ES+A192KW` | ECDH-ES using Concat KDF and CEK wrapped with "A192KW"                        |
| `ECDH-ES+A256KW` | ECDH-ES using Concat KDF and CEK wrapped with "A256KW"                        |
| `A128GCMKW` | Key wrapping with AES GCM using 128-bit key<sup><b>3</b></sup>                |
| `A192GCMKW` | Key wrapping with AES GCM using 192-bit key<sup><b>3</b></sup>                |
| `A256GCMKW` | Key wrapping with AES GCM using 256-bit key<sup><b>3</b></sup>                |
| `PBES2-HS256+A128KW` | PBES2 with HMAC SHA-256 and "A128KW" wrapping<sup><b>3</b></sup>              |
| `PBES2-HS384+A192KW` | PBES2 with HMAC SHA-384 and "A192KW" wrapping<sup><b>3</b></sup>              |
| <code>PBES2&#8209;HS512&plus;A256KW</code> | PBES2 with HMAC SHA-512 and "A256KW" wrapping<sup><b>3</b></sup>              |

<sup><b>3</b>. Requires Java 8 or a compatible JCA Provider (like BouncyCastle) in the runtime classpath.</sup>

These are all represented as constants in the `io.jsonwebtoken.Jwts.KEY` registry singleton as
implementations of the `io.jsonwebtoken.security.KeyAlgorithm` interface.

But 17 algorithms are a lot to choose from.  When would you use them?  The sections below describe when you might
choose each category of algorithms and how they behave.

<a name="jwe-alg-rsa"></a>
##### RSA Key Encryption

The JWT RSA key management algorithms `RSA1_5`, `RSA-OAEP`, and `RSA-OAEP-256` are used when you want to use the
JWE recipient's RSA _public_ key during encryption.  This ensures that only the JWE recipient can decrypt 
and read the JWE (using their RSA `private` key).

During JWE creation, these algorithms:

* Generate a new secure-random Content Encryption Key (CEK) suitable for the desired [encryption algorithm](#jwe-enc).
* Encrypt the JWE payload with the desired encryption algorithm using the new CEK, producing the JWE payload ciphertext.
* Encrypt the CEK itself with the specified RSA key wrap algorithm using the JWE recipient's RSA public key.
* Embed the payload ciphertext and encrypted CEK in the resulting JWE.

During JWE decryption, these algorithms:

* Retrieve the encrypted Content Encryption Key (CEK) embedded in the JWE.
* Decrypt the encrypted CEK with the discovered RSA key unwrap algorithm using the JWE recipient's RSA private key, 
  producing the decrypted Content Encryption Key (CEK).
* Decrypt the JWE ciphertext payload with the JWE's identified [encryption algorithm](#jwe-enc) using the decrypted CEK.

> **Warning**
>
> RFC 7518 Sections [4.2](https://www.rfc-editor.org/rfc/rfc7518.html#section-4.2) and 
> [4.3](https://www.rfc-editor.org/rfc/rfc7518.html#section-4.3) _require_ (mandate) that RSA keys >= 2048 bits 
> MUST be used with these algorithms. JJWT will throw an exception if it detects weaker keys being used.

<a name="jwe-alg-aes"></a>
##### AES Key Encryption

The JWT AES key management algorithms `A128KW`, `A192KW`, `A256KW`, `A128GCMKW`, `A192GCMKW`, and `A256GCMKW` are 
used when you have a symmetric secret key, but you don't want to use that secret key to directly 
encrypt/decrypt the JWT.

Instead, a new secure-random key is generated each time a JWE is created, and that new/random key is used to directly 
encrypt/decrypt the JWT payload.  The secure-random key is itself encrypted with your symmetric secret key
using the AES Wrap algorithm, and the encrypted key is embedded in the resulting JWE.

This allows the JWE to be encrypted with a random short-lived key, reducing material exposure of the potentially 
longer-lived symmetric secret key.

Because these particular algorithms use a symmetric secret key, they are best suited when the JWE creator and 
receiver are the same, ensuring the secret key does not need to be shared with multiple parties.

During JWE creation, these algorithms:

* Generate a new secure-random Content Encryption Key (CEK) suitable for the desired [encryption algorithm](#jwe-enc).
* Encrypt the JWE payload with the desired encryption algorithm using the new CEK, producing the JWE payload ciphertext.
* Encrypt the CEK itself with the specified AES key algorithm (either AES Key Wrap or AES with GCM encryption), 
  producing the encrypted CEK.
* Embed the payload ciphertext and encrypted CEK in the resulting JWE.

During JWE decryption, these algorithms:

* Retrieve the encrypted Content Encryption Key (CEK) embedded in the JWE.
* Decrypt the encrypted CEK with the discovered AES key algorithm using the symmetric secret key.
* Decrypt the JWE ciphertext payload with the JWE's identified [encryption algorithm](#jwe-enc) using the decrypted CEK.

> **Warning**
>
> The symmetric key used for the AES key algorithms MUST be 128, 192 or 256 bits as required by the specific AES 
> key algorithm.  JJWT will throw an exception if it detects weaker keys than what is required.

<a name="jwe-alg-dir"></a>
##### Direct Key Encryption

The JWT `dir` (direct) key management algorithm is used when you have a symmetric secret key, and you want to use it
to directly encrypt the JWT payload.

Because this algorithm uses a symmetric secret key, it is best suited when the JWE creator and receiver are the
same, ensuring the secret key does not need to be shared with multiple parties.

This is the simplest key algorithm for direct encryption that does not perform any key encryption.  It is essentially
a 'no op' key algorithm, allowing the shared key to be used to directly encrypt the JWT payload.

During JWE creation, this algorithm:

* Encrypts the JWE payload with the desired encryption algorithm directly using the symmetric secret key, 
  producing the JWE payload ciphertext.
* Embeds the payload ciphertext in the resulting JWE.

Note that because this algorithm does not produce an encrypted key value, an encrypted CEK is _not_ embedded in the 
resulting JWE.

During JWE decryption, this algorithm decrypts the JWE ciphertext payload with the JWE's 
identified [encryption algorithm](#jwe-enc) directly using the symmetric secret key.  No encrypted CEK is used.

> **Warning**
>
> The symmetric secret key MUST be 128, 192 or 256 bits as required by the associated 
> [AEAD encryption algorithm](#jwe-enc) used to encrypt the payload. JJWT will throw an exception if it detects 
> weaker keys than what is required.

<a name="jwe-alg-pbes2"></a>
##### Password-Based Key Encryption

The JWT password-based key encryption algorithms `PBES2-HS256+A128KW`, `PBES2-HS384+A192KW`, and `PBES2-HS512+A256KW`
are used when you want to use a password (character array) to encrypt and decrypt a JWT.

However, because passwords are usually too weak or problematic to use directly in cryptographic contexts, these
algorithms utilize key derivation techniques with work factors (e.g. computation iterations) and secure-random salts
to produce stronger cryptographic keys suitable for cryptographic operations.

This allows the payload to be encrypted with a random short-lived cryptographically-stronger key, reducing the need to 
expose the longer-lived (and potentially weaker) password.

Because these algorithms use a secret password, they are best suited when the JWE creator and receiver are the
same, ensuring the secret password does not need to be shared with multiple parties.

During JWE creation, these algorithms:

* Generate a new secure-random Content Encryption Key (CEK) suitable for the desired [encryption algorithm](#jwe-enc).
* Encrypt the JWE payload with the desired encryption algorithm using the new CEK, producing the JWE payload ciphertext.
* Derive a 'key encryption key' (KEK) with the desired "PBES2 with HMAC SHA" algorithm using the password, a suitable 
  number of computational iterations, and a secure-random salt value.
* Encrypt the generated CEK with the corresponding AES Key Wrap algorithm using the password-derived KEK.
* Embed the payload ciphertext and encrypted CEK in the resulting JWE.

> **Note**
>
> **Secure defaults**: When using these algorithms, if you do not specify a work factor (i.e. number of computational
> iterations), JJWT will automatically use an 
> [OWASP PBKDF2 recommended](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#pbkdf2)
> default appropriate for the specified `PBES2` algorithm.

During JWE decryption, these algorithms:

* Retrieve the encrypted Content Encryption Key (CEK) embedded in the JWE.
* Derive the 'key encryption key' (KEK) with the discovered "PBES2 with HMAC SHA" algorithm using the password and the
  number of computational iterations and secure-random salt value discovered in the JWE header.
* Decrypt the encrypted CEK with the corresponding AES Key Unwrap algorithm using the password-derived KEK.
* Decrypt the JWE ciphertext payload with the JWE's identified [encryption algorithm](#jwe-enc) using the decrypted CEK.

<a name="jwe-alg-ecdhes"></a>
##### Elliptic Curve Diffie-Hellman Ephemeral Static Key Agreement (ECDH-ES)

The JWT Elliptic Curve Diffie-Hellman Ephemeral Static key agreement algorithms `ECDH-ES`, `ECDH-ES+A128KW`, 
`ECDH-ES+A192KW`, and `ECDH-ES+A256KW` are used when you want to use the JWE recipient's Elliptic Curve _public_ key 
during encryption.  This ensures that only the JWE recipient can decrypt and read the JWE (using their Elliptic Curve 
_private_ key).

During JWE creation, these algorithms:

* Obtain the Content Encryption Key (CEK) used to encrypt the JWE payload as follows:
  * Inspect the JWE recipient's Elliptic Curve public key and determine its Curve.
  * Generate a new secure-random ephemeral Ellipic Curve public/private key pair on this same Curve.
  * Add the ephemeral EC public key to the JWE 
    [epk header](https://www.rfc-editor.org/rfc/rfc7518.html#section-4.6.1.1) for inclusion in the final JWE.
  * Produce an ECDH shared secret with the ECDH Key Agreement algorithm using the JWE recipient's EC public key
    and the ephemeral EC private key.
  * Derive a symmetric secret key with the Concat Key Derivation Function 
    ([NIST.800-56A](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-56Ar2.pdf), Section 5.8.1) using
    this ECDH shared secret and any provided
    [PartyUInfo](https://www.rfc-editor.org/rfc/rfc7518.html#section-4.6.1.2) and/or
    [PartyVInfo](https://www.rfc-editor.org/rfc/rfc7518.html#section-4.6.1.3).
  * If the key algorithm is `ECDH-ES`:
    * Use the Concat KDF-derived symmetric secret key directly as the Content Encryption Key (CEK). No encrypted key 
      is created, nor embedded in the resulting JWE.
  * Otherwise, if the key algorithm is `ECDH-ES+A128KW`, `ECDH-ES+A192KW`, or `ECDH-ES+A256KW`:
    * Generate a new secure-random Content Encryption Key (CEK) suitable for the desired [encryption algorithm](#jwe-enc).
    * Encrypt this new CEK with the corresponding AES Key Wrap algorithm using the Concat KDF-derived secret key, 
      producing the encrypted CEK.
    * Embed the encrypted CEK in the resulting JWE.
* Encrypt the JWE payload with the desired encryption algorithm using the obtained CEK, producing the JWE payload 
  ciphertext.
* Embed the payload ciphertext in the resulting JWE.

During JWE decryption, these algorithms:

* Obtain the Content Encryption Key (CEK) used to decrypt the JWE payload as follows:
  * Retrieve the required ephemeral Elliptic Curve public key from the JWE's 
    [epk header](https://www.rfc-editor.org/rfc/rfc7518.html#section-4.6.1.1).
  * Ensure the ephemeral EC public key exists on the same curve as the JWE recipient's EC private key.
  * Produce the ECDH shared secret with the ECDH Key Agreement algorithm using the JWE recipient's EC private key
    and the ephemeral EC public key.
  * Derive a symmetric secret key with the Concat Key Derivation Function
    ([NIST.800-56A](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-56Ar2.pdf), Section 5.8.1) using
    this ECDH shared secret and any 
    [PartyUInfo](https://www.rfc-editor.org/rfc/rfc7518.html#section-4.6.1.2) and/or
    [PartyVInfo](https://www.rfc-editor.org/rfc/rfc7518.html#section-4.6.1.3) found in the JWE header.
  * If the key algorithm is `ECDH-ES`:
    * Use the Concat KDF-derived secret key directly as the Content Encryption Key (CEK). No encrypted key is used.
  * Otherwise, if the key algorithm is `ECDH-ES+A128KW`, `ECDH-ES+A192KW`, or `ECDH-ES+A256KW`:
      * Obtain the encrypted key ciphertext embedded in the JWE.
      * Decrypt the encrypted key ciphertext with the associated AES Key Unwrap algorithm using the Concat KDF-derived
        secret key, producing the unencrypted Content Encryption Key (CEK).
* Decrypt the JWE payload ciphertext with the JWE's discovered encryption algorithm using the obtained CEK.

<a name="jwe-create"></a>
### Creating a JWE

Now that we know the difference between a JWE Encryption Algorithm and a JWE Key Management Algorithm, how do we use
them to encrypt a JWT?

You create an encrypted JWT (called a 'JWE') as follows:

1. Use the `Jwts.builder()` method to create a `JwtBuilder` instance.
2. Call `JwtBuilder` methods to set the `payload` content or claims and any [header](#jws-create-header) parameters as desired.
3. Call the `encryptWith` method, specifying the Key, Key Algorithm, and Encryption Algorithm you want to use.
4. Finally, call the `compact()` method to compact and encrypt, producing the final jwe.

For example:

```java
String jwe = Jwts.builder()                              // (1)

    .subject("Bob")                                      // (2) 

    .encryptWith(key, keyAlgorithm, encryptionAlgorithm) // (3)
     
    .compact();                                          // (4)
```

Before calling `compact()`,  you may set any [header](#jws-create-header) parameters and [claims](#jws-create-claims) 
exactly the same way as described for JWS.

<a name="jwe-compression"></a>
#### JWE Compression

If your JWT payload or Claims set is large (contains a lot of data), you might want to compress the JWE to reduce 
its size.  Please see the main [Compression](#compression) section to see how to compress and decompress JWTs.

<a name="jwe-read"></a>
### Reading a JWE

You read (parse) a JWE as follows:

1. Use the `Jwts.parser()` method to create a `JwtParserBuilder` instance.
2. Call either [keyLocator](#key-locator) or `decryptWith` methods to determine the key used to decrypt the JWE.
4. Call the `JwtParserBuilder`'s `build()` method to create a thread-safe `JwtParser`.
5. Parse the jwe string with the `JwtParser`'s `parseClaimsJwe` or `parseContentJwe` method.
6. Wrap the entire call is in a try/catch block in case decryption or integrity verification fails.

For example:

```java
Jwe<Claims> jwe;

try {
    jwe = Jwts.parser()         // (1)

    .keyLocator(keyLocator)     // (2) dynamically lookup decryption keys based on each JWE    
    //.decryptWith(key)         //     or a static key used to decrypt all encountered JWEs
        
    .build()                    // (3)
    .parseClaimsJwe(jweString); // (4) or parseContentJwe(jweString);
    
    // we can safely trust the JWT
     
catch (JwtException ex) {       // (5)
    
    // we *cannot* use the JWT as intended by its creator
}
```

> **Note**
>
> **Type-safe JWEs:**
> * If you are expecting a JWE with a Claims `payload`, call the `JwtParser`'s `parseClaimsJwe` method.
> * If you are expecting a JWE with a content `payload`, call the `JwtParser`'s `parseContentJwe` method.

<a name="jwe-read-key"></a>
#### Decryption Key

The most important thing to do when reading a JWE is to specify the key used during decryption.  If decryption or
integrity protection checks fail, the JWT cannot be safely trusted and should be discarded.

So which key do we use for decryption?

* If the jwe was encrypted _directly_ with a `SecretKey`, the same `SecretKey` must be specified on the 
  `JwtParserBuilder`. For example:

  ```java
  Jwts.parser()
      
    .decryptWith(secretKey) // <----
    
    .build()
    .parseClaimsJwe(jweString);
  ```
* If the jwe was encrypted using a key produced by a Password-based key derivation `KeyAlgorithm`, the same 
  `Password` must be specified on the `JwtParserBuilder`. For example:

  ```java
  Password password = Keys.password(passwordChars);
  
  Jwts.parser()
      
    .decryptWith(password) // <---- an `io.jsonwebtoken.security.Password` instance
    
    .build()
    .parseClaimsJwe(jweString);
  ```
* If the jwe was encrypted with a key produced by an asymmetric `KeyAlgorithm`, the corresponding `PrivateKey` (not 
  the `PublicKey`) must be specified on the `JwtParserBuilder`.  For example:

  ```java
  Jwts.parser()
      
    .decryptWith(privateKey) // <---- a `PrivateKey`, not a `PublicKey`
    
    .build()
    .parseClaimsJws(jweString);
  ```

<a name="jwe-key-locator"></a>
#### Decryption Key Locator

What if your application doesn't use just a single `SecretKey` or `KeyPair`? What
if JWEs can be created with different `SecretKey`s, `Password`s or public/private keys, or a combination of all of 
them?  How do you know which key to specify if you can't inspect the JWT first?

In these cases, you can't call the `JwtParserBuilder`'s `decryptWith` method with a single key - instead, you'll need
to use a Key `Locator`.  Please see the [Key Lookup](#key-locator) section to see how to dynamically obtain different 
keys when parsing JWSs or JWEs.

<a name="jwe-key-pkcs11"></a>
#### ECDH-ES Decryption with PKCS11 PrivateKeys

The JWT `ECDH-ES`, `ECDH-ES+A128KW`, `ECDH-ES+A192KW`, and `ECDH-ES+A256KW` key algorithms validate JWE input using
public key information, even when using `PrivateKey`s to decrypt.  Ordinarily this is automatically performed
by JJWT when your `PrivateKey` instances implement the 
[ECKey](https://docs.oracle.com/en/java/javase/17/docs/api/java.base/java/security/interfaces/ECKey.html) or 
[EdECKey](https://docs.oracle.com/en/java/javase/17/docs/api/java.base/java/security/interfaces/EdECKey.html)
(or BouncyCastle equivalent) interfaces, which is the case for most JCA `Provider` implementations.

However, if your decryption `PrivateKey`s are stored in a Hardware Security Module (HSM) and/or you use the 
[SunPKCS11 Provider](https://docs.oracle.com/en/java/javase/17/security/pkcs11-reference-guide1.html#GUID-6DA72F34-6C6A-4F7D-ADBA-5811576A9331),
it is likely that your `PrivateKey` instances _do not_ implement `ECKey`.

In these cases, you need to provide both the PKCS11 `PrivateKey` and it's companion `PublicKey` during decryption
by using the `Keys.wrap` method. For example: 
for example:

```java
KeyPair pair = getMyPkcs11KeyPair();
PrivateKey priv = pair.getPrivate();
PublicKey pub = pair.getPublic(); // must implement ECKey or EdECKey or BouncyCastle equivalent
PrivateKey decryptionKey = Keys.wrap(priv, pub);
```

You then use the resulting `decryptionKey` (not `priv`) with the `JwtParserBuilder` or as the return value from 
a custom [Key Locator](#key-locator) implementation.  For example:

```java
PrivateKey decryptionKey = Keys.wrap(pkcs11PrivateKey, pkcs11PublicKey);

Jwts.parser()
    .decryptWith(decryptionKey) // <----
    .build()
    .parseClaimsJwe(jweString);
```

Or as the return value from your key locator:

```java
Jwts.parser()
    .keyLocator(keyLocator) // your keyLocator.locate(header) would return Keys.wrap(privateKey, publicKey)
    .build()
    .parseClaimsJwe(jweString);
```

<a name="jwe-read-decompression"></a>
#### JWE Decompression

If a JWE is compressed using the `DEF` ([DEFLATE](https://www.rfc-editor.org/rfc/rfc1951)) or `GZIP` 
([GZIP](https://www.rfc-editor.org/rfc/rfc1952.html)) compression algorithms, it will automatically be decompressed
after decryption, and there is nothing you need to configure.

If, however, a custom compression algorithm was used to compress the JWE, you will need to tell the
`JwtParserBuilder` how to resolve your `CompressionAlgorithm` to decompress the JWT.

Please see the [Compression](#compression) section below to see how to decompress JWTs during parsing.

<a name="jwk"></a>
## JSON Web Keys (JWKs)

[JSON Web Keys](https://www.rfc-editor.org/rfc/rfc7517.html) (JWKs) are JSON serializations of cryptographic keys, 
allowing key material to be embedded in JWTs or transmitted between parties in a standard JSON-based text format. They
are essentially a JSON-based alternative to other text-based key formats, such as the
[DER, PEM and PKCS12](https://serverfault.com/a/9717) text strings or files commonly used when configuring TLS on web
servers, for example.

For example, an identity web service may expose its RSA or Elliptic Curve Public Keys to 3rd parties in the JWK format.
A client may then parse the public key JWKs to verify the service's [JWS](#jws) tokens, as well as send encrypted 
information to the service using [JWE](#jwe)s.

JWKs can be converted to and from standard Java `Key` types as expected using the same builder/parser patterns we've
seen for JWTs.

<a name="jwk-create"></a>
### Create a JWK

You create a JWK as follows:

1. Use the `Jwks.builder()` method to create a `JwkBuilder` instance.
2. Call the `key` method with the Java key you wish to represent as a JWK.
3. Call builder methods to set any additional key fields or metadata, such as a `kid` (Key ID), X509 Certificates, 
   etc as desired.
4. Call the `build()` method to produce the resulting JWK.

For example:

```java
SecretKey key = getSecretKey();     // or RSA or EC PublicKey or PrivateKey
SecretJwk = Jwks.builder().key(key) // (1) and (2)
        
    .id("mySecretKeyId")            // (3)
    // ... etc ...    
    
    .build();                       // (4)
```

#### JWK from a Map

If you have a `Map<String,?>` of name/value pairs that reflect an existing JWK, you add them and build a type-safe
`Jwk` instance:

```java
Map<String,?> jwkValues = getMyJwkMap();

Jwk<?> jwk = Jwks.builder().add(jwkValues).build();
```

<a name="jwk-read"></a>
### Read a JWK

You can read/parse a JWK by building a `JwkParser` and parsing the JWK JSON string with its `parse` method:

```java
String json = getJwkJsonString();
Jwk<?> jwk = Jwks.parser()
    //.provider(aJcaProvider)     // optional
    //.deserializer(deserializer) // optional
    .build()                      // create the parser
    .parse(json);                 // actually parse the JSON

Key key = jwk.toKey();            // convert to a Java Key instance
```
As shown above you can specify a custom JCA Provider or [JSON deserializer](#json) in the same way as the `JwtBuilder`.

<a name="jwk-private"></a>
### PrivateKey JWKs

Unlike Java, the JWA specification requires a private JWKs to contain _both_ public key _and_ private key material
(see [RFC 7518, Section 6.1.1](https://www.rfc-editor.org/rfc/rfc7518.html#section-6.2.2) and 
[RFC 7518, Section 6.3.2](https://www.rfc-editor.org/rfc/rfc7518.html#section-6.3.2)).

In this sense, a private JWK (represented as a `PrivateJwk` or a subtype, such as `RsaPrivateJwk`, `EcPrivateJwk`, etc) 
can be thought of more like a Java `KeyPair` instance.  Consequently, when creating a `PrivateJwk` instance, 
the `PrivateKey`'s corresponding `PublicKey` is required.

<a name="jwk-private-public"></a>
#### Private JWK `PublicKey`

If you do not provide a `PublicKey` when creating a `PrivateJwk`, JJWT will automatically derive the `PublicKey` from 
the `PrivateKey` instance if possible. However, because this can add 
some computing time, it is typically recommended to provide the `PublicKey` when possible to avoid this extra work.

For example:

```java
RSAPrivateKey rsaPrivateKey = getRSAPrivateKey(); // or ECPrivateKey

RsaPrivateJwk jwk = Jwks.builder().key(rsaPrivateKey)

        //.publicKey(rsaPublicKey)  // optional, but recommended to avoid extra computation work
        
        .build();
```

<a name="jwk-private-keypair"></a>
#### Private JWK from KeyPair

If you have a Java `KeyPair` instance, then you have both the public and private key material necessary to create a
`PrivateJwk`. For example:

```java
KeyPair rsaKeyPair = getRSAKeyPair();
RsaPrivateJwk rsaPrivJwk = Jwks.builder().rsaKeyPair(rsaKeyPair).build();

KeyPair ecKeyPair = getECKeyPair();
EcPrivateJwk ecPrivJwk = Jwks.builder().ecKeyPair(ecKeyPair).build();

KeyPair edEcKeyPair = getEdECKeyPair();
OctetPrivateJwk edEcPrivJwk = Jwks.builder().octetKeyPair(edEcKeyPair).build();
```

Note that:
* An exception will thrown when calling `rsaKeyPair` if the specified `KeyPair` instance does not contain
`RSAPublicKey` and `RSAPrivateKey` instances.  
* Similarly, an exception will be thrown when calling `ecKeyPair` if
the `KeyPair` instance does not contain `ECPublicKey` and `ECPrivateKey` instances.  
* Finally, an exception will be 
thrown when calling `octetKeyPair` if the `KeyPair` instance does not contain X25519, X448, Ed25519, or Ed448 keys
(introduced in JDK 11 and 15 or when using BouncyCastle).

<a name="jwk-private-topub"></a>
#### Private JWK Public Conversion

Because private JWKs contain public key material, you can always obtain the private JWK's corresponding public JWK and
Java `PublicKey` or `KeyPair`.  For example:

```java
RsaPrivateJwk privateJwk = Jwks.builder().key(rsaPrivateKey).build(); // or ecPrivateKey or edEcPrivateKey

// Get the matching public JWK and/or PublicKey:
RsaPublicJwk pubJwk = privateJwk.toPublicJwk();       // JWK instance
RSAPublicKey pubKey = pubJwk.toKey();                 // Java PublicKey instance
KeyPair pair = privateJwk.toKeyPair();                // io.jsonwebtoken.security.KeyPair retains key types
java.security.KeyPair jdkPair = pair.toJavaKeyPair(); // does not retain pub/private key types
```

<a name="jwk-thumbprint"></a>
### JWK Thumbprints

A [JWK Thumbprint](https://www.rfc-editor.org/rfc/rfc7638.html) is a digest (aka hash) of a canonical JSON 
representation of a JWK's public properties. 'Canonical' in this case means that only RFC-specified values in any JWK
are used in an exact order thumbprint calculation.  This ensures that anyone can calculate a JWK's same exact 
thumbprint, regardless of custom fields or JSON key/value ordering differences in a JWK.

All `Jwk` instances support [JWK Thumbprint](https://www.rfc-editor.org/rfc/rfc7638.html)s via the
`thumbprint()` and `thumbprint(HashAlgorithm)` methods:

```java
HashAlgorithm hashAlg = Jwks.HASH.SHA256; // or SHA384, SHA512, etc.

Jwk<?> jwk = Jwks.builder(). /* ... */ .build();

JwkThumbprint sha256Thumbprint = jwk.thumbprint(); // SHA-256 thumbprint by default

JwkThumbprint anotherThumbprint = jwk.thumbprint(Jwks.HASH.SHA512); // or a specified hash algorithm
```

The resulting `JwkThumbprint` instance provides some useful methods:

* `jwkThumbprint.toByteArray()`: the thumbprint's actual digest bytes - i.e. the raw output from the hash algorithm
* `jwkThumbprint.toString()`: the digest bytes as a Base64URL-encoded string
* `jwkThumbprint.getHashAlgorithm()`: the specific `HashAlgorithm` used to compute the thumbprint. Many standard IANA
                                      hash algorithms are available as constants in the `Jwts.HASH` utility class.
* `jwkThumbprint.toURI()`: the thumbprint's canonical URI as defined by the [JWK Thumbprint URI](https://www.rfc-editor.org/rfc/rfc9278.html) specification

<a name="jwk-thumbprint-kid"></a>
#### JWK Thumbprint as a Key ID

Because a thumbprint is an order-guaranteed unique digest of a JWK, JWK thumbprints are often used as convenient
unique identifiers for a JWK (e.g. the JWK's `kid` (Key ID) value). These identifiers can be useful when
[locating keys](#key-locator) for JWS signature verification or JWE decryption, for example.

For example:

```java
String kid = jwk.thumbprint().toString(); // Thumbprint bytes as a Base64URL-encoded string
Key key = findKey(kid);
assert jwk.toKey().equals(key);
```

However, because `Jwk` instances are immutable, you can't set the key id after the JWK is created. For example, the
following is not possible:

```java
String kid = jwk.thumbprint().toString();
jwk.setId(kid) // Jwks are immutable - there is no `setId` method
```

Instead, you may use the `idFromThumbprint` methods on the `JwkBuilder` when creating a `Jwk`:

```java
Jwk<?> jwk = Jwks.builder().key(aKey)

    .idFromThumbprint() // or idFromThumbprint(HashAlgorithm)

    .build();
```

Calling either `idFromThumbprint` method will ensure that calling `jwk.getId()` equals `thumbprint.toString()`
(which is `Encoders.BASE64URL.encode(thumbprint.toByteArray())`).

<a name="jwk-thumbprint-uri"></a>
#### JWK Thumbprint URI

A JWK's thumbprint's canonical URI as defined by the [JWK Thumbprint URI](https://www.rfc-editor.org/rfc/rfc9278.html) 
specification may be obtained by calling the thumbprint's `toURI()` method:

```java
URI canonicalThumbprintURI = jwk.thumbprint().toURI();
```

Per the RFC specification, if you call `canonicalThumbprintURI.toString()`, you would see a string that looks like this:

```text
urn:ietf:params:oauth:jwk-thumbprint:HASH_ALG_ID:BASE64URL_DIGEST
```

where:
* `urn:ietf:params:oauth:jwk-thumbprint:` is the URI scheme+prefix
* `HASH_ALG_ID` is the standard identifier used to compute the thumbprint as defined in the
  [IANA Named Information Hash Algorithm Registry](https://www.iana.org/assignments/named-information/named-information.xhtml).
  This is the same as `thumbprint.getHashAlgorithm().getId()`.
* `BASE64URL_DIGEST` is the Base64URL-encoded thumbprint bytes, equal to `jwkThumbprint.toString()`.

<a name="jwk-security"></a>
### JWK Security Considerations

Because they contain secret or private key material, `SecretJwk` and `PrivateJwk` (e.g. `RsaPrivateJwk`,  
`EcPrivateJwk`, etc) instances should be used with great care and never accidentally transmitted to 3rd parties.

Even so, JJWT's `Jwk` implementations will suppress certain values in `toString()` output for safety as described 
next.

<a name="jwk-tostring"></a>
#### JWK `toString()` Safety

Because it would be incredibly easy to accidentally print key material to `System.out.println()` or application 
logs, all `Jwk` implementations will print redacted values instead of actual secret or private key material.

For example, consider the following Secret JWK JSON example from 
[RFC 7515, Appendix A.1.1](https://www.rfc-editor.org/rfc/rfc7515#appendix-A.1.1):

```json
{
  "kty": "oct",
  "k": "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow",
  "kid": "HMAC key used in https://www.rfc-editor.org/rfc/rfc7515#appendix-A.1.1 example."
}
```

The `k` value (`AyAyM1SysPpby...`) reflects secure key material and should never be accidentially
exposed.

If you were to parse this JSON as a `Jwk`, calling `toString()` will _NOT_ print this value.  It will 
instead print the string literal `<redacted>` for any secret or private key data field.  For example:

```java
String json = getExampleSecretKeyJson();
Jwk<?> jwk = Jwks.parser().build().parse(json);

System.out.printn(jwk);
```

This code would print the following string literal to the System console:

```text
{kty=oct, k=<redacted>, kid=HMAC key used in https://www.rfc-editor.org/rfc/rfc7515#appendix-A.1.1 example.}
```

This is true for all secret or private key members in `SecretJwk` and `PrivateJwk` (e.g. `RsaPrivateJwk`, 
`EcPrivateJwk`, etc) instances.

<a name="compression"></a>
## Compression

> **Warning**
>
> **The JWT specifications tandardizes compression for JWEs (Encrypted JWTs) ONLY, however JJWT supports it for JWS
> (Signed JWTs) as well**.
> 
> If you are positive that a JWT you create with JJWT will _also_ be parsed with JJWT, 
> you can use this feature with both JWEs and JWSs, otherwise it is best to only use it for JWEs.

If a JWT's `payload` is sufficiently large - that is, it is a large content byte array or JSON with a lot of 
name/value pairs (or individual values are very large or verbose) - you can reduce the size of the compact JWT by 
compressing the payload.

This might be important to you if the resulting JWT is used in a URL for example, since URLs are best kept under 
4096 characters due to browser, user mail agent, or HTTP gateway compatibility issues.  Smaller JWTs also help reduce 
bandwidth utilization, which may or may not be important depending on your application's volume or needs.

If you want to compress your JWT, you can use the `JwtBuilder`'s  `compressWith(CompressionAlgorithm)` method.  For 
example:

```java
Jwts.builder()
   
   .compressWith(Jwts.ZIP.DEF) // DEFLATE compression algorithm
   
   // .. etc ...
```

If you use any of the algorithm constants in the `Jwts.ZIP` class, that's it, you're done.  You don't have to 
do anything during parsing or configure the `JwtParserBuilder` for compression - JJWT will automatically decompress 
the payload as expected.

<a name="compression-custom"></a>
### Custom Compression Algorithm

If the default `Jwts.ZIP` compression algorithms are not suitable for your needs, you can create your own 
`CompressionAlgorithm` implementation(s).

Just as you would with the default algorithms, you may specify that you want a JWT compressed by calling the 
`JwtBuilder`'s `compressWith` method, supplying your custom implementation instance.  For example:

```java
CompressionAlgorithm myAlg = new MyCompressionAlgorithm();

Jwts.builder()
   
   .compressWith(myAlg) // <----
   
   // .. etc ...
```

When you call `compressWith`, the JWT `payload` will be compressed with your algorithm, and the 
[`zip` (Compression Algorithm)](https://www.rfc-editor.org/rfc/rfc7516.html#section-4.1.3) 
header will automatically be set to the value returned by your algorithm's `algorithm.getId()` method as 
required by the JWT specification.

However, the `JwtParser` needs to be aware of this custom algorithm as well, so it can use it while parsing. You do this 
by calling the `JwtParserBuilder`'s `addCompressionAlgorithms` method.  For example:

```java
CompressionAlgorithm myAlg = new MyCompressionAlgorithm();

Jwts.parser()

    .addCompressionAlgorithms(Collections.of(myAlg)) // <----
    
    // .. etc ...
```

This adds additional `CompressionAlgorithm` implementations to the parser's overall total set of supported compression
algorithms (which already includes all of the `Jwts.ZIP` algorithms by default).

The parser will then automatically check to see if the JWT `zip` header has been set to see if a compression
algorithm has been used to compress the JWT.  If set, the parser will automatically look up your 
`CompressionAlgorithm` by its `getId()` value, and use it to decompress the JWT.

<a name="json"></a>
## JSON Support

A `JwtBuilder` will serialize the `Header` and `Claims` maps (and potentially any Java objects they 
contain) to JSON with a `Serializer<Map<String, ?>>` instance.  Similarly, a `JwtParser` will 
deserialize JSON into the `Header` and `Claims` using a `Deserializer<Map<String, ?>>` instance.

If you don't explicitly configure a `JwtBuilder`'s `Serializer` or a `JwtParserBuilder`'s `Deserializer`, JJWT will 
automatically attempt to discover and use the following JSON implementations if found in the runtime classpath.  
They are checked in order, and the first one found is used:

1. Jackson: This will automatically be used if you specify `io.jsonwebtoken:jjwt-jackson` as a project runtime 
   dependency.  Jackson supports POJOs as claims with full marshaling/unmarshaling as necessary.
   
2. Gson: This will automatically be used if you specify `io.jsonwebtoken:jjwt-gson` as a project runtime dependency.
   Gson also supports POJOs as claims with full marshaling/unmarshaling as necessary. 
   
3. JSON-Java (`org.json`): This will be used automatically if you specify `io.jsonwebtoken:jjwt-orgjson` as a 
   project runtime dependency.
   
   > **Note**
   > 
   > `org.json` APIs are natively enabled in Android environments so this is the recommended JSON processor for
   > Android applications _unless_ you want to use POJOs as claims.  The `org.json` library supports simple
   > Object-to-JSON marshaling, but it *does not* support JSON-to-Object unmarshalling.

**If you want to use POJOs as claim values, use either the `io.jsonwebtoken:jjwt-jackson` or 
`io.jsonwebtoken:jjwt-gson` dependency** (or implement your own Serializer and Deserializer if desired). **But beware**, 
Jackson will force a sizable (> 1 MB) dependency to an Android application thus increasing the app download size for 
mobile users.

<a name="json-custom"></a>
### Custom JSON Processor

If you don't want to use JJWT's runtime dependency approach, or just want to customize how JSON serialization and 
deserialization works, you can implement the `Serializer` and `Deserializer` interfaces and specify instances of
them on the `JwtBuilder` and `JwtParserBuilder` respectively.  For example:

When creating a JWT:

```java
Serializer<Map<String,?>> serializer = getMySerializer(); //implement me

Jwts.builder()

    .serializer(serializer)
    
    // ... etc ...
```

When reading a JWT:

```java
Deserializer<Map<String,?>> deserializer = getMyDeserializer(); //implement me

Jwts.parser()

    .deserializer(deserializer)
    
    // ... etc ...
```

<a name="json-jackson"></a>
### Jackson JSON Processor

If you want to use Jackson for JSON processing, just including the `io.jsonwebtoken:jjwt-jackson` dependency as a
runtime dependency is all that is necessary in most projects, since Gradle and Maven will automatically pull in
the necessary Jackson dependencies as well.

After including this dependency, JJWT will automatically find the Jackson implementation on the runtime classpath and 
use it internally for JSON parsing.  There is nothing else you need to do - JJWT will automatically create a new
Jackson ObjectMapper for its needs as required.

However, if you have an application-wide Jackson `ObjectMapper` (as is typically recommended for most applications), 
you can configure JJWT to use your own `ObjectMapper` instead.

You do this by declaring the `io.jsonwebtoken:jjwt-jackson` dependency with **compile** scope (not runtime 
scope which is the typical JJWT default).  That is:

**Maven**

```xml
<dependency>
    <groupId>io.jsonwebtoken</groupId>
    <artifactId>jjwt-jackson</artifactId>
    <version>JJWT_RELEASE_VERSION</version>
    <scope>compile</scope> <!-- Not runtime -->
</dependency>
```

**Gradle or Android**

```groovy
dependencies {
    implementation 'io.jsonwebtoken:jjwt-jackson:JJWT_RELEASE_VERSION'
}
```

And then you can specify the `JacksonSerializer` using your own `ObjectMapper` on the `JwtBuilder`:

```java
ObjectMapper objectMapper = getMyObjectMapper(); //implement me

String jws = Jwts.builder()

    .serializer(new JacksonSerializer(objectMapper))
    
    // ... etc ...
```

and the `JacksonDeserializer` using your `ObjectMapper` on the `JwtParserBuilder`:

```java
ObjectMapper objectMapper = getMyObjectMapper(); //implement me

Jwts.parser()

    .deserializer(new JacksonDeserializer(objectMapper))
    
    // ... etc ...
```

<a name="json-jackson-custom-types"></a>
#### Parsing of Custom Claim Types

By default JJWT will only convert simple claim types: String, Date, Long, Integer, Short and Byte.  If you need to 
deserialize other types you can configure the `JacksonDeserializer` by passing a `Map` of claim names to types in 
through a constructor. For example:

```java
new JacksonDeserializer(Maps.of("user", User.class).build())
```

This would trigger the value in the `user` claim to be deserialized into the custom type of `User`.  Given the claims 
payload of:

```json
{
    "issuer": "https://example.com/issuer",
    "user": {
      "firstName": "Jill",
      "lastName": "Coder"
    }
}
```

The `User` object could be retrieved from the `user` claim with the following code:

```java
Jwts.parser()

    .deserializer(new JacksonDeserializer(Maps.of("user", User.class).build())) // <-----

    .build()

    .parseClaimsJwt(aJwtString)

    .getPayload()
    
    .get("user", User.class) // <-----
```

> **Note**
> 
> Using this constructor is mutually exclusive with the `JacksonDeserializer(ObjectMapper)` constructor
> [described above](#json-jackson). This is because JJWT configures an `ObjectMapper` directly and could have negative
> consequences for a shared `ObjectMapper` instance. This should work for most applications, if you need a more advanced
> parsing options, [configure the mapper directly](#json-jackson).

<a name="json-gson"></a>
### Gson JSON Processor

If you want to use Gson for JSON processing, just including the `io.jsonwebtoken:jjwt-gson` dependency as a
runtime dependency is all that is necessary in most projects, since Gradle and Maven will automatically pull in
the necessary Gson dependencies as well.

After including this dependency, JJWT will automatically find the Gson implementation on the runtime classpath and 
use it internally for JSON parsing.  There is nothing else you need to do - just declaring the dependency is 
all that is required, no code or config is necessary.

If you're curious, JJWT will automatically create an internal default Gson instance for its own needs as follows:

```java
new GsonBuilder()
    .registerTypeHierarchyAdapter(io.jsonwebtoken.lang.Supplier.class, GsonSupplierSerializer.INSTANCE)    
    .disableHtmlEscaping().create();
```

The `registerTypeHierarchyAdapter` builder call is required to serialize JWKs with secret or private values.

However, if you prefer to use a different Gson instance instead of JJWT's default, you can configure JJWT to use your 
own - just don't forget to register the necessary JJWT type hierarchy adapter.

You do this by declaring the `io.jsonwebtoken:jjwt-gson` dependency with **compile** scope (not runtime 
scope which is the typical JJWT default).  That is:

**Maven**

```xml
<dependency>
    <groupId>io.jsonwebtoken</groupId>
    <artifactId>jjwt-gson</artifactId>
    <version>JJWT_RELEASE_VERSION</version>
    <scope>compile</scope> <!-- Not runtime -->
</dependency>
```

**Gradle or Android**

```groovy
dependencies {
    implementation 'io.jsonwebtoken:jjwt-gson:JJWT_RELEASE_VERSION'
}
```

And then you can specify the `GsonSerializer` using your own `Gson` instance on the `JwtBuilder`:

```java

Gson gson = new GsonBuilder()
    // don't forget this line!:    
    .registerTypeHierarchyAdapter(io.jsonwebtoken.lang.Supplier.class, GsonSupplierSerializer.INSTANCE)
    .disableHtmlEscaping().create();

String jws = Jwts.builder()

    .serializer(new GsonSerializer(gson))
    
    // ... etc ...
```

and the `GsonDeserializer` using your `Gson` instance on the `JwtParser`:

```java
Gson gson = getGson(); //implement me

Jwts.parser()

    .deserializer(new GsonDeserializer(gson))
    
    // ... etc ...
```

Again, as shown above, it is critical to create your `Gson` instance using the `GsonBuilder` and include the line:

```java
.registerTypeHierarchyAdapter(io.jsonwebtoken.lang.Supplier.class, GsonSupplierSerializer.INSTANCE)
```

to ensure JWK serialization works as expected.

<a name="base64"></a>
## Base64 Support

JJWT uses a very fast pure-Java [Base64](https://tools.ietf.org/html/rfc4648) codec for Base64 and 
Base64Url encoding and decoding that is guaranteed to work deterministically in all JDK and Android environments.

You can access JJWT's encoders and decoders using the `io.jsonwebtoken.io.Encoders` and `io.jsonwebtoken.io.Decoders` 
utility classes.

`io.jsonwebtoken.io.Encoders`:

* `BASE64` is an RFC 4648 [Base64](https://tools.ietf.org/html/rfc4648#section-4) encoder
* `BASE64URL` is an RFC 4648 [Base64URL](https://tools.ietf.org/html/rfc4648#section-5) encoder

`io.jsonwebtoken.io.Decoders`:

* `BASE64` is an RFC 4648 [Base64](https://tools.ietf.org/html/rfc4648#section-4) decoder
* `BASE64URL` is an RFC 4648 [Base64URL](https://tools.ietf.org/html/rfc4648#section-5) decoder

<a name="base64-security"></a>
### Understanding Base64 in Security Contexts

All cryptographic operations, like encryption and message digest calculations, result in binary data - raw byte arrays.

Because raw byte arrays cannot be represented natively in JSON, the JWT
specifications employ the Base64URL encoding scheme to represent these raw byte values in JSON documents or compound 
structures like a JWT.

This means that the Base64 and Base64URL algorithms take a raw byte array and converts the bytes into a string suitable 
to use in text documents and protocols like HTTP.  These algorithms can also convert these strings back
into the original raw byte arrays for decryption or signature verification as necessary.

That's nice and convenient, but there are two very important properties of Base64 (and Base64URL) text strings that 
are critical to remember when they are used in security scenarios like with JWTs:

* [Base64 is not encryption](#base64-not-encryption)
* [Changing Base64 characters](#base64-changing-characters) **does not automatically invalidate data**.

<a name="base64-not-encryption"></a>
#### Base64 is not encryption
 
Base64-encoded text is _not_ encrypted. 

While a byte array representation can be converted to text with the Base64 algorithms, 
anyone in the world can take Base64-encoded text, decode it with any standard Base64 decoder, and obtain the 
underlying raw byte array data.  No key or secret is required to decode Base64 text - anyone can do it.

Based on this, when encoding sensitive byte data with Base64 - like a shared or private key - **the resulting
string is NOT safe to expose publicly**.

A base64-encoded key is still sensitive information and must be kept as secret and as safe as the original source
of the bytes (e.g. a Java `PrivateKey` or `SecretKey` instance).

After Base64-encoding data into a string, it is possible to then encrypt the string to keep it safe from prying 
eyes if desired, but this is different.  Encryption is not encoding.  They are separate concepts.

<a name="base64-changing-characters"></a>
#### Changing Base64 Characters

In an effort to see if signatures or encryption is truly validated correctly, some try to edit a JWT
string - particularly the Base64-encoded signature part - to see if the edited string fails security validations.

This conceptually makes sense: change the signature string, you would assume that signature validation would fail.

_But this doesn't always work. Changing base64 characters is an invalid test_.

Why?

Because of the way the Base64 algorithm works, there are multiple Base64 strings that can represent the same raw byte 
array.

Going into the details of the Base64 algorithm is out of scope for this documentation, but there are many good 
Stackoverflow [answers](https://stackoverflow.com/questions/33663113/multiple-strings-base64-decoded-to-same-byte-array?noredirect=1&lq=1)
and [JJWT issue comments](https://github.com/jwtk/jjwt/issues/211#issuecomment-283076269) that explain this in detail. 
Here's one [good answer](https://stackoverflow.com/questions/29941270/why-do-base64-decode-produce-same-byte-array-for-different-strings):

> Remember that Base64 encodes each 8 bit entity into 6 bit chars. The resulting string then needs exactly 
> 11 * 8 / 6 bytes, or 14 2/3 chars. But you can't write partial characters. Only the first 4 bits (or 2/3 of the 
> last char) are significant. The last two bits are not decoded. Thus all of:
>
>     dGVzdCBzdHJpbmo
>     dGVzdCBzdHJpbmp
>     dGVzdCBzdHJpbmq
>     dGVzdCBzdHJpbmr
> All decode to the same 11 bytes (116, 101, 115, 116, 32, 115, 116, 114, 105, 110, 106).

As you can see by the above 4 examples, they all decode to the same exact 11 bytes.  So just changing one or two
characters at the end of a Base64 string may not work and can often result in an invalid test.

<a name="base64-invalid-characters"></a>
##### Adding Invalid Characters

JJWT's default Base64/Base64URL decoders automatically ignore illegal Base64 characters located in the beginning and 
end of an encoded string. Therefore prepending or appending invalid characters like `{` or `]` or similar will also 
not fail JJWT's signature checks either.  Why?

Because such edits - whether changing a trailing character or two, or appending invalid characters - do not actually 
change the _real_ signature, which in cryptographic contexts, is always a byte array. Instead, tests like these 
change a text encoding of the byte array, and as we covered above, they are different things.

So JJWT 'cares' more about the real byte array and less about its text encoding because that is what actually matters
in cryptographic operations.  In this sense, JJWT follows the [Robustness Principle](https://en.wikipedia.org/wiki/Robustness_principle)
in being _slightly_ lenient on what is accepted per the rules of Base64, but if anything in the real underlying 
byte array is changed, then yes, JJWT's cryptographic assertions will definitely fail.

To help understand JJWT's approach, we have to remember why signatures exist. From our documentation above on 
[signing JWTs](#jws):

> * guarantees it was created by someone we know (it is authentic), as well as
> * guarantees that no-one has manipulated or changed it after it was created (its integrity is maintained).

Just prepending or appending invalid text to try to 'trick' the algorithm doesn't change the integrity of the 
underlying claims or signature byte arrays, nor the authenticity of the claims byte array, because those byte 
arrays are still obtained intact.

Please see [JJWT Issue #518](https://github.com/jwtk/jjwt/issues/518) and its referenced issues and links for more 
information.

<a name="base64-custom"></a>
### Custom Base64

If for some reason you want to specify your own Base64Url encoder and decoder, you can use the `JwtBuilder`
`encoder` method to set the encoder:

```java
Encoder<byte[], String> encoder = getMyBase64UrlEncoder(); //implement me

String jws = Jwts.builder()

    .encoder(encoder)
    
    // ... etc ...
```

and the `JwtParserBuilder`'s `decoder` method to set the decoder:

```java
Decoder<String, byte[]> decoder = getMyBase64UrlDecoder(); //implement me

Jwts.parser()

    .decoder(decoder)
    
    // ... etc ...
```

<a name="examples"></a>
## Examples

* [JWS Signed with HMAC](#example-jws-hs)
* [JWS Signed with RSA](#example-jws-rsa)
* [JWS Signed with ECDSA](#example-jws-ecdsa)
* [JWS Signed with EdDSA](#example-jws-eddsa)
* [JWE Encrypted Directly with a SecretKey](#example-jwe-dir)
* [JWE Encrypted with RSA](#example-jwe-rsa)
* [JWE Encrypted with AES Key Wrap](#example-jwe-aeskw)
* [JWE Encrypted with ECDH-ES](#example-jwe-ecdhes)
* [JWE Encrypted with a Password](#example-jwe-password)
* [SecretKey JWK](#example-jwk-secret)
* [RSA Public JWK](#example-jwk-rsapub)
* [RSA Private JWK](#example-jwk-rsapriv)
* [Elliptic Curve Public JWK](#example-jwk-ecpub)
* [Elliptic Curve Private JWK](#example-jwk-ecpriv)
* [Edwards Elliptic Curve Public JWK](#example-jwk-edpub)
* [Edwards Elliptic Curve Private JWK](#example-jwk-edpriv)

<a name="example-jws-hs"></a>
### JWT Signed with HMAC

This is an example showing how to digitally sign a JWT using an [HMAC](https://en.wikipedia.org/wiki/HMAC) 
(hash-based message authentication code).  The JWT specifications define 3 standard HMAC signing algorithms:

* `HS256`: HMAC with SHA-256. This requires a 256-bit (32 byte) `SecretKey` or larger.
* `HS384`: HMAC with SHA-384. This requires a 384-bit (48 byte) `SecretKey` or larger.
* `HS512`: HMAC with SHA-512. This requires a 512-bit (64 byte) `SecretKey` or larger.

Example:

```java
// Create a test key suitable for the desired HMAC-SHA algorithm:
MacAlgorithm alg = Jwts.SIG.HS512; //or HS384 or HS256
SecretKey key = alg.key().build();

String message = "Hello World!";
byte[] content = message.getBytes(StandardCharsets.UTF_8);

// Create the compact JWS:
String jws = Jwts.builder().content(content, "text/plain").signWith(key, alg).compact();

// Parse the compact JWS:
content = Jwts.parser().verifyWith(key).build().parseContentJws(jws).getPayload();

assert message.equals(new String(content, StandardCharsets.UTF_8));
```

<a name="example-jws-rsa"></a>
### JWT Signed with RSA

This is an example showing how to digitally sign and verify a JWT using RSA cryptography. The JWT specifications 
define [6 standard RSA signing algorithms](#jws-alg).  All 6 require that [RSA keys 2048-bits or larger](#jws-key-rsa)
must be used.

In this example, Bob will sign a JWT using his RSA private key, and Alice can verify it came from Bob using Bob's RSA
public key:

```java
// Create a test key suitable for the desired RSA signature algorithm:
SignatureAlgorithm alg = Jwts.SIG.RS512; //or PS512, RS256, etc...
KeyPair pair = alg.keyPair().build();

// Bob creates the compact JWS with his RSA private key:
String jws = Jwts.builder().subject("Alice")
    .signWith(pair.getPrivate(), alg) // <-- Bob's RSA private key
    .compact();

// Alice receives and verifies the compact JWS came from Bob:
String subject = Jwts.parser()
    .verifyWith(pair.getPublic()) // <-- Bob's RSA public key
    .build().parseClaimsJws(jws).getPayload().getSubject();

assert "Alice".equals(subject);
```

<a name="example-jws-ecdsa"></a>
### JWT Signed with ECDSA

This is an example showing how to digitally sign and verify a JWT using the Elliptic Curve Digital Signature Algorithm.
The JWT specifications define [3 standard ECDSA signing algorithms](#jws-alg):

* `ES256`: ECDSA using P-256 and SHA-256. This requires an EC Key exactly 256 bits (32 bytes) long.
* `ES384`: ECDSA using P-384 and SHA-384. This requires an EC Key exactly 384 bits (48 bytes) long.
* `ES512`: ECDSA using P-521 and SHA-512. This requires an EC Key exactly 521 bits (65 or 66 bytes depending on format) long.

In this example, Bob will sign a JWT using his EC private key, and Alice can verify it came from Bob using Bob's EC
public key:

```java
// Create a test key suitable for the desired ECDSA signature algorithm:
SignatureAlgorithm alg = Jwts.SIG.ES512; //or ES256 or ES384
KeyPair pair = alg.keyPair().build();

// Bob creates the compact JWS with his EC private key:
String jws = Jwts.builder().subject("Alice")
    .signWith(pair.getPrivate(), alg) // <-- Bob's EC private key
    .compact();

// Alice receives and verifies the compact JWS came from Bob:
String subject = Jwts.parser()
    .verifyWith(pair.getPublic()) // <-- Bob's EC public key
    .build().parseClaimsJws(jws).getPayload().getSubject();

assert "Alice".equals(subject);
```

<a name="example-jws-eddsa"></a>
### JWT Signed with EdDSA

This is an example showing how to digitally sign and verify a JWT using the 
[Edwards Curve Digital Signature Algorithm](https://www.rfc-editor.org/rfc/rfc8032) using
`Ed25519` or `Ed448` keys.

> **Note**
>
> **The `Ed25519` and `Ed448` algorithms require JDK 15 or a compatible JCA Provider
> (like BouncyCastle) in the runtime classpath.**
>
> If you are using JDK 14 or earlier and you want to use them, see
> the [Installation](#Installation) section to see how to enable BouncyCastle.

The `EdDSA` signature algorithm is defined for JWS in [RFC 8037, Section 3.1](https://www.rfc-editor.org/rfc/rfc8037#section-3.1)
using keys for two Edwards curves:

* `Ed25519`: `EdDSA` using curve `Ed25519`. `Ed25519` algorithm keys must be 256 bits (32 bytes) long and produce 
             signatures 512 bits (64 bytes) long.
* `Ed448`: `EdDSA` using curve `Ed448`. `Ed448` algorithm keys must be 456 bits (57 bytes) long and produce signatures 
           912 bits (114 bytes) long.

In this example, Bob will sign a JWT using his Edwards Curve private key, and Alice can verify it came from Bob 
using Bob's Edwards Curve public key:

```java
// Create a test key suitable for the EdDSA signature algorithm using Ed25519 or Ed448 keys:
Curve curve = Jwks.CRV.Ed25519; //or Ed448
KeyPair pair = curve.keyPair().build();

// Bob creates the compact JWS with his Edwards Curve private key:
String jws = Jwts.builder().subject("Alice")
    .signWith(pair.getPrivate(), Jwts.SIG.EdDSA) // <-- Bob's Edwards Curve private key w/ EdDSA
    .compact();

// Alice receives and verifies the compact JWS came from Bob:
String subject = Jwts.parser()
    .verifyWith(pair.getPublic()) // <-- Bob's Edwards Curve public key
    .build().parseClaimsJws(jws).getPayload().getSubject();

assert "Alice".equals(subject);
```

<a name="example-jwe-dir"></a>
### JWT Encrypted Directly with a SecretKey

This is an example showing how to encrypt a JWT [directly using a symmetric secret key](#jwe-alg-dir).  The
JWT specifications define [6 standard AEAD Encryption algorithms](#jwe-enc):

* `A128GCM`: AES GCM using a 128-bit (16 byte) `SecretKey` or larger.
* `A192GCM`: AES GCM using a 192-bit (24 byte) `SecretKey` or larger.
* `A256GCM`: AES GCM using a 256-bit (32 byte) `SecretKey` or larger.
* `A128CBC-HS256`: [AES_128_CBC_HMAC_SHA_256](https://www.rfc-editor.org/rfc/rfc7518.html#section-5.2.3) using a 
  256-bit (32 byte) `SecretKey`.
* `A192CBC-HS384`: [AES_192_CBC_HMAC_SHA_384](https://www.rfc-editor.org/rfc/rfc7518.html#section-5.2.4) using a
  384-bit (48 byte) `SecretKey`.
* `A256CBC-HS512`: [AES_256_CBC_HMAC_SHA_512](https://www.rfc-editor.org/rfc/rfc7518.html#section-5.2.5) using a
  512-bit (64 byte) `SecretKey`.

The AES GCM (`A128GCM`, `A192GCM` and `A256GCM`) algorithms are strongly recommended - they are faster and more
efficient than the `A*CBC-HS*` variants, but they do require JDK 8 or later (or JDK 7 + BouncyCastle).

Example:

```java
// Create a test key suitable for the desired payload encryption algorithm:
// (A*GCM algorithms are recommended, but require JDK >= 8 or BouncyCastle)
AeadAlgorithm enc = Jwts.ENC.A256GCM; //or A128GCM, A192GCM, A256CBC-HS512, etc...
SecretKey key = enc.key().build();

String message = "Live long and prosper.";
byte[] content = message.getBytes(StandardCharsets.UTF_8);

// Create the compact JWE:
String jwe = Jwts.builder().content(content, "text/plain").encryptWith(key, enc).compact();

// Parse the compact JWE:
content = Jwts.parser().decryptWith(key).build().parseContentJwe(jwe).getPayload();

assert message.equals(new String(content, StandardCharsets.UTF_8));
```

<a name="example-jwe-rsa"></a>
### JWT Encrypted with RSA

This is an example showing how to encrypt and decrypt a JWT using RSA cryptography.

Because RSA cannot encrypt much data, RSA is used to encrypt and decrypt a secure-random key, and that generated key 
in turn is used to actually encrypt the payload as described in the [RSA Key Encryption](jwe-alg-rsa) section 
above. As such, RSA Key Algorithms must be paired with an AEAD Encryption Algorithm, as shown below.

In this example, Bob will encrypt a JWT using Alice's RSA public key to ensure only she may read it.  Alice can then 
decrypt the JWT using her RSA private key:

```java
// Create a test KeyPair suitable for the desired RSA key algorithm:
KeyPair pair = Jwts.SIG.RS512.keyPair().build();

// Choose the key algorithm used encrypt the payload key:
KeyAlgorithm<PublicKey, PrivateKey> alg = Jwts.KEY.RSA_OAEP_256; //or RSA_OAEP or RSA1_5
// Choose the Encryption Algorithm to encrypt the payload:
AeadAlgorithm enc = Jwts.ENC.A256GCM; //or A192GCM, A128GCM, A256CBC-HS512, etc...

// Bob creates the compact JWE with Alice's RSA public key so only she may read it:
String jwe = Jwts.builder().audience("Alice")
    .encryptWith(pair.getPublic(), alg, enc) // <-- Alice's RSA public key
    .compact();

// Alice receives and decrypts the compact JWE:
String audience = Jwts.parser()
    .decryptWith(pair.getPrivate()) // <-- Alice's RSA private key
    .build().parseClaimsJwe(jwe).getPayload().getAudience();

assert "Alice".equals(audience);
```

<a name="example-jwe-aeskw"></a>
### JWT Encrypted with AES Key Wrap

This is an example showing how to encrypt and decrypt a JWT using AES Key Wrap algorithms.

These algorithms use AES to encrypt and decrypt a secure-random key, and that generated key in turn is used to actually encrypt
the payload as described in the [AES Key Encryption](jwe-alg-aes) section above. This allows the payload to be 
encrypted with a random short-lived key, reducing material exposure of the potentially longer-lived symmetric secret 
key.  This approach requires the AES Key Wrap algorithms to be paired with an AEAD content encryption algorithm, 
as shown below.

The AES GCM Key Wrap algorithms (`A128GCMKW`, `A192GCMKW` and `A256GCMKW`) are preferred - they are faster and more
efficient than the `A*KW` variants, but they do require JDK 8 or later (or JDK 7 + BouncyCastle).

```java
// Create a test SecretKey suitable for the desired AES Key Wrap algorithm:
SecretKeyAlgorithm alg = Jwts.KEY.A256GCMKW; //or A192GCMKW, A128GCMKW, A256KW, etc...
SecretKey key = alg.key().build();

// Chooose the Encryption Algorithm used to encrypt the payload:
AeadAlgorithm enc = Jwts.ENC.A256GCM; //or A192GCM, A128GCM, A256CBC-HS512, etc...

// Create the compact JWE:
String jwe = Jwts.builder().issuer("me").encryptWith(key, alg, enc).compact();

// Parse the compact JWE:
String issuer = Jwts.parser().decryptWith(key).build()
    .parseClaimsJwe(jwe).getPayload().getIssuer();

assert "me".equals(issuer);
```

<a name="example-jwe-ecdhes"></a>
### JWT Encrypted with ECDH-ES

This is an example showing how to encrypt and decrypt a JWT using Elliptic Curve Diffie-Hellman Ephmeral Static 
Key Agreement (ECDH-ES) algorithms.

These algorithms use ECDH-ES to encrypt and decrypt a secure-random key, and that 
generated key in turn is used to actually encrypt the payload as described in the 
[Elliptic Curve Diffie-Hellman Ephemeral Static Key Agreement](jwe-alg-ecdhes) section above. Because of this, ECDH-ES 
Key Algorithms must be paired with an AEAD Encryption Algorithm, as shown below.

In this example, Bob will encrypt a JWT using Alice's Elliptic Curve public key to ensure only she may read it.  
Alice can then decrypt the JWT using her Elliptic Curve private key:

```java
// Create a test KeyPair suitable for the desired EC key algorithm:
KeyPair pair = Jwts.SIG.ES512.keyPair().build();

// Choose the key algorithm used encrypt the payload key:
KeyAlgorithm<PublicKey, PrivateKey> alg = Jwts.KEY.ECDH_ES_A256KW; //ECDH_ES_A192KW, etc.
// Choose the Encryption Algorithm to encrypt the payload:
AeadAlgorithm enc = Jwts.ENC.A256GCM; //or A192GCM, A128GCM, A256CBC-HS512, etc...

// Bob creates the compact JWE with Alice's EC public key so only she may read it:
String jwe = Jwts.builder().audience("Alice")
    .encryptWith(pair.getPublic(), alg, enc) // <-- Alice's EC public key
    .compact();

// Alice receives and decrypts the compact JWE:
String audience = Jwts.parser()
    .decryptWith(pair.getPrivate()) // <-- Alice's EC private key
    .build().parseClaimsJwe(jwe).getPayload().getAudience();

assert "Alice".equals(audience);
```

<a name="example-jwe-password"></a>
### JWT Encrypted with a Password

This is an example showing how to encrypt and decrypt a JWT using Password-based key-derivation algorithms.

These algorithms use a password to securely derive a random key, and that derived random key in turn is used to actually 
encrypt the payload as described in the [Password-based Key Encryption](jwe-alg-pbes2) section above. This allows 
the payload to be encrypted with a random short-lived cryptographically-stronger key, reducing the need to
expose the longer-lived (and potentially weaker) password.  

This approach requires the Password-based Key Wrap algorithms to be paired with an AEAD content encryption algorithm, 
as shown below.

```java
//DO NOT use this example password in a real app, it is well-known to password crackers:
String pw = "correct horse battery staple";
Password password = Keys.password(pw.toCharArray());

// Choose the desired PBES2 key derivation algorithm:
KeyAlgorithm<Password, Password> alg = Jwts.KEY.PBES2_HS512_A256KW; //or PBES2_HS384_A192KW or PBES2_HS256_A128KW

// Optionally choose the number of PBES2 computational iterations to use to derive the key.
// This is optional - if you do not specify a value, JJWT will automatically choose a value 
// based on your chosen PBES2 algorithm and OWASP PBKDF2 recommendations here: 
// https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#pbkdf2
// 
// If you do specify a value, ensure the iterations are large enough for your desired alg
//int pbkdf2Iterations = 120000; //for HS512. Needs to be much higher for smaller hash algs.

// Choose the Encryption Algorithm used to encrypt the payload:
AeadAlgorithm enc = Jwts.ENC.A256GCM; //or A192GCM, A128GCM, A256CBC-HS512, etc...

// Create the compact JWE:
String jwe = Jwts.builder().issuer("me")
    // Optional work factor is specified in the header:
    //.header().pbes2Count(pbkdf2Iterations)).and()
    .encryptWith(password, alg, enc)
    .compact();

// Parse the compact JWE:
String issuer = Jwts.parser().decryptWith(password)
    .build().parseClaimsJwe(jwe).getPayload().getIssuer();

assert "me".equals(issuer);
```

<a name="example-jwk-secret"></a>
### SecretKey JWK

Example creating and parsing a secret JWK:

```java
SecretKey key = Jwts.SIG.HS512.key().build(); // or HS384 or HS256
SecretJwk jwk = Jwks.builder().key(key).idFromThumbprint().build();

assert jwk.getId().equals(jwk.thumbprint().toString());
assert key.equals(jwk.toKey());

byte[] utf8Bytes = new JacksonSerializer().serialize(jwk); // or GsonSerializer(), etc
String jwkJson = new String(utf8Bytes, StandardCharsets.UTF_8);
Jwk<?> parsed = Jwks.parser().build().parse(jwkJson);

assert parsed instanceof SecretJwk;
assert jwk.equals(parsed);
```

<a name="example-jwk-rsapub"></a>
### RSA Public JWK

Example creating and parsing an RSA Public JWK:

```java
RSAPublicKey key = (RSAPublicKey)Jwts.SIG.RS512.keyPair().build().getPublic();
RsaPublicJwk jwk = Jwks.builder().key(key).idFromThumbprint().build();

assert jwk.getId().equals(jwk.thumbprint().toString());
assert key.equals(jwk.toKey());

byte[] utf8Bytes = new JacksonSerializer().serialize(jwk); // or GsonSerializer(), etc
String jwkJson = new String(utf8Bytes, StandardCharsets.UTF_8);
Jwk<?> parsed = Jwks.parser().build().parse(jwkJson);

assert parsed instanceof RsaPublicJwk;
assert jwk.equals(parsed);
```

<a name="example-jwk-rsapriv"></a>
### RSA Private JWK

Example creating and parsing an RSA Private JWK:

```java
KeyPair pair = Jwts.SIG.RS512.keyPair().build();
RSAPublicKey pubKey = (RSAPublicKey) pair.getPublic();
RSAPrivateKey privKey = (RSAPrivateKey) pair.getPrivate();

RsaPrivateJwk privJwk = Jwks.builder().key(privKey).idFromThumbprint().build();
RsaPublicJwk pubJwk = privJwk.toPublicJwk();

assert privJwk.getId().equals(privJwk.thumbprint().toString());
assert pubJwk.getId().equals(pubJwk.thumbprint().toString());
assert privKey.equals(privJwk.toKey());
assert pubKey.equals(pubJwk.toKey());

byte[] utf8Bytes = new JacksonSerializer().serialize(privJwk); // or GsonSerializer(), etc
String jwkJson = new String(utf8Bytes, StandardCharsets.UTF_8);
Jwk<?> parsed = Jwks.parser().build().parse(jwkJson);

assert parsed instanceof RsaPrivateJwk;
assert privJwk.equals(parsed);
```

<a name="example-jwk-ecpub"></a>
### Elliptic Curve Public JWK

Example creating and parsing an Elliptic Curve Public JWK:

```java
ECPublicKey key = (ECPublicKey) Jwts.SIG.ES512.keyPair().build().getPublic();
EcPublicJwk jwk = Jwks.builder().key(key).idFromThumbprint().build();

assert jwk.getId().equals(jwk.thumbprint().toString());
assert key.equals(jwk.toKey());

byte[] utf8Bytes = new JacksonSerializer().serialize(jwk); // or GsonSerializer(), etc
String jwkJson = new String(utf8Bytes, StandardCharsets.UTF_8);
Jwk<?> parsed = Jwks.parser().build().parse(jwkJson);

assert parsed instanceof EcPublicJwk;
assert jwk.equals(parsed);
```

<a name="example-jwk-ecpriv"></a>
### Elliptic Curve Private JWK

Example creating and parsing an Elliptic Curve Private JWK:

```java
KeyPair pair = Jwts.SIG.ES512.keyPair().build();
ECPublicKey pubKey = (ECPublicKey) pair.getPublic();
ECPrivateKey privKey = (ECPrivateKey) pair.getPrivate();

EcPrivateJwk privJwk = Jwks.builder().key(privKey).idFromThumbprint().build();
EcPublicJwk pubJwk = privJwk.toPublicJwk();

assert privJwk.getId().equals(privJwk.thumbprint().toString());
assert pubJwk.getId().equals(pubJwk.thumbprint().toString());
assert privKey.equals(privJwk.toKey());
assert pubKey.equals(pubJwk.toKey());

byte[] utf8Bytes = new JacksonSerializer().serialize(privJwk); // or GsonSerializer(), etc
String jwkJson = new String(utf8Bytes, StandardCharsets.UTF_8);
Jwk<?> parsed = Jwks.parser().build().parse(jwkJson);

assert parsed instanceof EcPrivateJwk;
assert privJwk.equals(parsed);
```

<a name="example-jwk-edpub"></a>
### Edwards Elliptic Curve Public JWK

Example creating and parsing an Edwards Elliptic Curve (Ed25519, Ed448, X25519, X448) Public JWK
(the JWT [RFC 8037](https://www.rfc-editor.org/rfc/rfc8037) specification calls these `Octet` keys, hence the 
`OctetPublicJwk` interface names):

```java
PublicKey key = Jwks.CRV.Ed25519.keyPair().build().getPublic(); // or Ed448, X25519, X448
OctetPublicJwk<PublicKey> jwk = builder().octetKey(key).idFromThumbprint().build();

assert jwk.getId().equals(jwk.thumbprint().toString());
assert key.equals(jwk.toKey());

byte[] utf8Bytes = new JacksonSerializer().serialize(jwk); // or GsonSerializer(), etc
String jwkJson = new String(utf8Bytes, StandardCharsets.UTF_8);
Jwk<?> parsed = Jwks.parser().build().parse(jwkJson);

assert parsed instanceof OctetPublicJwk;
assert jwk.equals(parsed);
```

<a name="example-jwk-edpriv"></a>
### Edwards Elliptic Curve Private JWK

Example creating and parsing an Edwards Elliptic Curve (Ed25519, Ed448, X25519, X448) Private JWK
(the JWT [RFC 8037](https://www.rfc-editor.org/rfc/rfc8037) specification calls these `Octet` keys, hence the
`OctetPrivateJwk` and `OctetPublicJwk` interface names):

```java
KeyPair pair = Jwks.CRV.Ed448.keyPair().build(); // or Ed25519, X25519, X448
PublicKey pubKey = pair.getPublic();
PrivateKey privKey = pair.getPrivate();

OctetPrivateJwk<PrivateKey, PublicKey> privJwk = builder().octetKey(privKey).idFromThumbprint().build();
OctetPublicJwk<PublicKey> pubJwk = privJwk.toPublicJwk();

assert privJwk.getId().equals(privJwk.thumbprint().toString());
assert pubJwk.getId().equals(pubJwk.thumbprint().toString());
assert privKey.equals(privJwk.toKey());
assert pubKey.equals(pubJwk.toKey());

byte[] utf8Bytes = new JacksonSerializer().serialize(privJwk); // or GsonSerializer(), etc
String jwkJson = new String(utf8Bytes, StandardCharsets.UTF_8);
Jwk<?> parsed = Jwks.parser().build().parse(jwkJson);

assert parsed instanceof OctetPrivateJwk;
assert privJwk.equals(parsed);
```

## Learn More

- [JSON Web Token for Java and Android](https://stormpath.com/blog/jjwt-how-it-works-why/)
- [How to Create and Verify JWTs in Java](https://stormpath.com/blog/jwt-java-create-verify/)
- [Where to Store Your JWTs - Cookies vs HTML5 Web Storage](https://stormpath.com/blog/where-to-store-your-jwts-cookies-vs-html5-web-storage/)
- [Use JWT the Right Way!](https://stormpath.com/blog/jwt-the-right-way/)
- [Token Authentication for Java Applications](https://stormpath.com/blog/token-auth-for-java/)
- [JJWT Changelog](CHANGELOG.md)

## Author

Maintained by Les Hazlewood &amp; the extended Java community :heart:

<a name="license"></a>
## License

This project is open-source via the [Apache 2.0 License](http://www.apache.org/licenses/LICENSE-2.0).
