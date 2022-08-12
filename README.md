[![Build Status](https://github.com/jwtk/jjwt/actions/workflows/ci.yml/badge.svg?branch=master)](https://github.com/jwtk/jjwt/actions/workflows/ci.yml?query=branch%3Amaster)
[![Coverage Status](https://coveralls.io/repos/github/jwtk/jjwt/badge.svg?branch=master)](https://coveralls.io/github/jwtk/jjwt?branch=master)
[![Gitter](https://badges.gitter.im/jwtk/jjwt.svg)](https://gitter.im/jwtk/jjwt?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge)

# Java JWT: JSON Web Token for Java and Android

JJWT aims to be the easiest to use and understand library for creating and verifying JSON Web Tokens (JWTs) on the JVM
and Android.

JJWT is a pure Java implementation based exclusively on the [JWT](https://tools.ietf.org/html/rfc7519), 
[JWS](https://tools.ietf.org/html/rfc7515), [JWE](https://tools.ietf.org/html/rfc7516), 
[JWK](https://tools.ietf.org/html/rfc7517) and [JWA](https://tools.ietf.org/html/rfc7518) RFC specifications and 
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
    * [Claims](#jwt-create-claims)
      * [Standard Claims](#jwt-create-claims-standard)
      * [Custom Claims](#jwt-create-claims-custom)
      * [Claims Instance](#jwt-create-claims-instance)
      * [Claims Map](#jwt-create-claims-map)
  * [Compression](#jwt-compression)
* [Read a JWT](#jwt-read)
  * [Parsing Key](#jwt-read-key)
  * [Parsing Key Locator](#jwt-read-key-locator)
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
  * [Create a JWE](#jwe-create)
    * [JWE Compression](#jwe-compression)
  * [Read a JWE](#jwe-read)
    * [JWE Decryption Key](#jwe-read-key)
    * [JWE Decryption Key Locator](#jwe-key-locator)
    * [JWE Decompression](#jwe-read-decompression)
* [Key Lookup](#key-locator)
  * [Custom Key Locator](#key-locator-custom)
    * [Key Locator Strategy](#key-locator-custom-strategy)
    * [Key Locator Return Values](#key-locator-custom-retvals)
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

<a name="features"></a>
## Features

 * Fully functional on all JDKs and Android
 * Automatic security best practices and assertions
 * Easy to learn and read API
 * Convenient and readable [fluent](http://en.wikipedia.org/wiki/Fluent_interface) interfaces, great for IDE 
   auto-completion to write code quickly
 * Fully RFC specification compliant on all implemented functionality, tested against RFC-specified test vectors
 * Stable implementation with over 1,000+ tests and enforced 100% test code coverage.  Literally every single
   method, statement and conditional branch variant in the entire codebase is tested and required to pass on every build.
 * Creating, parsing and verifying digitally signed compact JWTs (aka JWSs) with all standard JWS algorithms:
   
   | Identifier | Signature Algorithm |
   | ------- | --- |
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

   <sup><b>1</b>. Requires Java 11 or a compatible JCA Provider (like BouncyCastle) in the runtime classpath.</sup>

 * Creating, parsing and decrypting encrypted compact JWTs (aka JWEs) with all standard JWE encryption algorithms:
 
   | Identifier | Encryption Algorithm |
   | --------------- | --- |
   | <code>A128CBC&#8209;HS256</code> | [AES_128_CBC_HMAC_SHA_256](https://datatracker.ietf.org/doc/html/rfc7518#section-5.2.3) authenticated encryption algorithm |
   | `A192CBC-HS384` | [AES_192_CBC_HMAC_SHA_384](https://datatracker.ietf.org/doc/html/rfc7518#section-5.2.4) authenticated encryption algorithm |
   | `A256CBC-HS512` | [AES_256_CBC_HMAC_SHA_512](https://datatracker.ietf.org/doc/html/rfc7518#section-5.2.5) authenticated encryption algorithm |
   | `A128GCM` | AES GCM using 128-bit key<sup><b>2</b></sup> |
   | `A192GCM` | AES GCM using 192-bit key<sup><b>2</b></sup> |
   | `A256GCM` | AES GCM using 256-bit key<sup><b>2</b></sup> |
   
   <sup><b>2</b>. Requires Java 8 or a compatible JCA Provider (like BouncyCastle) in the runtime classpath.</sup>

 * All Key Management Algorithms for obtaining JWE encryption and decryption keys: 
   
   | Identifier | Key Management Algorithm |
   | ----- | --- |   
   | `RSA1_5` | RSAES-PKCS1-v1_5 |
   | `RSA-OAEP` | RSAES OAEP using default parameters |
   | `RSA-OAEP-256` | RSAES OAEP using SHA-256 and MGF1 with SHA-256 |
   | `A128KW` | AES Key Wrap with default initial value using 128-bit key |
   | `A192KW` | AES Key Wrap with default initial value using 192-bit key |
   | `A256KW` | AES Key Wrap with default initial value using 256-bit key |
   | `dir` | Direct use of a shared symmetric key as the CEK |
   | `ECDH-ES` | Elliptic Curve Diffie-Hellman Ephemeral Static key agreement using Concat KDF |
   | `ECDH-ES+A128KW` | ECDH-ES using Concat KDF and CEK wrapped with "A128KW" |
   | `ECDH-ES+A192KW` | ECDH-ES using Concat KDF and CEK wrapped with "A192KW" |
   | `ECDH-ES+A256KW` | ECDH-ES using Concat KDF and CEK wrapped with "A256KW" |
   | `A128GCMKW` | Key wrapping with AES GCM using 128-bit key<sup><b>3</b></sup> |
   | `A192GCMKW` | Key wrapping with AES GCM using 192-bit key<sup><b>3</b></sup> |
   | `A256GCMKW` | Key wrapping with AES GCM using 256-bit key<sup><b>3</b></sup> |
   | `PBES2-HS256+A128KW` | PBES2 with HMAC SHA-256 and "A128KW" wrapping<sup><b>3</b></sup> |
   | `PBES2-HS384+A192KW` | PBES2 with HMAC SHA-384 and "A192KW" wrapping<sup><b>3</b></sup> |
   | <code>PBES2&#8209;HS512&plus;A256KW</code> | PBES2 with HMAC SHA-512 and "A256KW" wrapping<sup><b>3</b></sup> |
      
   <sup><b>3</b>. Requires Java 8 or a compatible JCA Provider (like BouncyCastle) in the runtime classpath.</sup>

 * Creating, parsing and verifying JSON Web Keys (JWKs) in all standard JWA key formats using native Java `Key` types:
   
   | JWK Key Format | Java `Key` Type | JJWT `Jwk` Type |
   |---------------|-----------------| --- |
   | Symmetric Key  | `SecretKey`    | `SecretJwk`     |
   | Elliptic Curve Public Key | `ECPublicKey`  | `EcPublicJwk`   |
   | Elliptic Curve Private Key | `ECPrivateKey` | `EcPrivateJwk`  |
   | RSA Public Key | `RSAPublicKey` | `RsaPublicJwk`  |
   | RSA Private Key | `RSAPrivateKey` | `RsaPrivateJwk` |

 * Convenience enhancements beyond the specification such as
    * Payload compression for any large JWT, not just JWEs
    * Claims assertions (requiring specific values)
    * Claim POJO marshaling and unmarshalling when using a compatible JSON parser (e.g. Jackson)
    * Secure Key generation based on desired JWA algorithms
    * and more...
    
<a name="features-unsupported"></a>
### Currently Unsupported Features

* [Non-compact](https://tools.ietf.org/html/rfc7515#section-7.2) serialization and parsing.

These features will be implemented in a future release.  Community contributions are welcome!

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
about something, please [ask your question here](https://stackoverflow.com/questions/ask?tags=jjwt&guided=false).

After asking your question, you may wish to join our [Slack](https://jwtk.slack.com/messages/CBNACTN3A) or
[Gittr](https://gitter.im/jwtk/jjwt) chat rooms, but note that they may not always be attended. You will usually
have a better chance of having your question answered by 
[asking your question here](https://stackoverflow.com/questions/ask?tags=jjwt&guided=false).
   
If you believe you have found a bug or would like to suggest a feature enhancement, please create a new GitHub issue, 
however:

**Please do not create a GitHub issue to ask a question.**  

We use GitHub Issues to track actionable work that requires changes to JJWT's design and/or codebase.  If you have a 
usability question, instead please 
[ask your question here](https://stackoverflow.com/questions/ask?tags=jjwt&guided=false), or try Slack or Gittr as 
described above.

**If a GitHub Issue is created that does not represent actionable work for JJWT's codebase, it will be promptly 
closed.**

<a name="help-issues"></a>
#### Bugs and Feature Requests

If you do not have a usability question and believe you have a legitimate bug or feature request, 
please do [create a new JJWT issue](https://github.com/jwtk/jjwt/issues/new).

If you feel like you'd like to help fix a bug or implement the new feature yourself, please read the Contributing 
section next before starting any work.

<a name="contributing"></a>
### Contributing

<a name="contributing-pull-requests"></a>
#### Pull Requests

Simple Pull Requests that fix anything other than JJWT core code (documentation, JavaDoc, typos, test cases, etc) are 
always appreciated and have a high likelihood of being merged quickly. Please send them!

However, if you want or feel the need to change JJWT's functionality or core code, please do not issue a pull request 
without [creating a new JJWT issue](https://github.com/jwtk/jjwt/issues/new) and discussing your desired 
changes **first**, _before you start working on it_.

It would be a shame to reject your earnest and genuinely-appreciated pull request if it might not align with the 
project's goals, design expectations or planned functionality.  We've sadly had to reject large PRs in the past because
they were out of sync with project or design expectations - all because the PR author didn't first check in with 
the team first before working on a solution.

So, please [create a new JJWT issue](https://github.com/jwtk/jjwt/issues/new) first to discuss, and then we can see if
(or how) a PR is warranted.  Thank you!

<a name="contributing-help-wanted"></a>
#### Help Wanted

If you would like to help, but don't know where to start, please visit the 
[Help Wanted Issues](https://github.com/jwtk/jjwt/labels/help%20wanted) page and pick any of the 
ones there, and we'll be happy to discuss and answer questions in the issue comments.

If any of those don't appeal to you, no worries! Any help you would like to offer would be 
appreciated based on the above caveats concerning [contributing pull reqeuests](#contributing-pull-requests). Feel free
to discuss or ask questions first if you're not sure. :)

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
images, documents, etc. And because a JWT `header` is a JSON `Object`, it would make sense that a JWT 
`payload` could also be a JSON `Object` as well.

In many cases, developers like the `payload` to be JSON that 
represents data about a user or computer or similar identity concept. When used this way, the `payload` is called a 
JSON `Claims` object, and each name/value pair within that object is called a `claim` - each piece of information 
within 'claims' something about an identity.

While it is useful to 'claim' something about an identity, really anyone can do that. What's important is that you 
_trust_ the claims by verifying they come from a person or computer you trust.

A nice feature of JWTs is that they can be secured in various ways. A JWT can be cryptographically signed (making it 
what we call a [JWS](https://tools.ietf.org/html/rfc7515)) or encrypted (making it a 
[JWE](https://tools.ietf.org/html/rfc7516)).  This adds a powerful layer of verifiability to the JWT - a
JWS or JWE recipient can have a high degree of confidence it comes from someone they trust
by verifying a signature or decrypting it. It is this feature of verifiability that makes JWT a good choice
for sending and receiving secure information, like identity claims.

Finally, JSON with whitespace for human readability is nice, but it doesn't make for a very efficient message
format.  Therefore, JWTs can be _compacted_ (and even compressed) to a minimal representation - basically 
Base64URL-encoded strings - so they can be transmitted around the web (such as in HTTP headers or URLs) more efficiently.

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

   In this case, the `header` indicates that the `HMAC using SHA-256` algorithm will be used to cryptographically sign 
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
both the header and the payload is publicly visible.  JWS just guarantees the data hasn't been changed by anyone - 
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
<!-- Uncomment this next dependency if you are using JDK 10 or earlier and you also want to use 
     RSASSA-PSS (PS256, PS384, PS512) algorithms.  JDK 11 or later does not require it for those algorithms:
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
    compile 'io.jsonwebtoken:jjwt-api:JJWT_RELEASE_VERSION'
    runtime 'io.jsonwebtoken:jjwt-impl:JJWT_RELEASE_VERSION',
    // Uncomment the next line if you want to use RSASSA-PSS (PS256, PS384, PS512) algorithms on JDK <= 10
    //'org.bouncycastle:bcprov-jdk15on:1.70',
    'io.jsonwebtoken:jjwt-jackson:JJWT_RELEASE_VERSION' // or 'io.jsonwebtoken:jjwt-gson:JJWT_RELEASE_VERSION' for gson
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
    // Uncomment the next line if you want to use RSASSA-PSS (PS256, PS384, PS512) algorithms
    // AND also enable the BouncyCastle provider as shown below
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

If you want to use JWT RSASSA-PSS algorithms (i.e. `PS256`, `PS384`, and `PS512`), or you just want to ensure your 
Android application is running an updated version of BouncyCastle, you will need to:
1. Uncomment the BouncyCastle dependency as commented above in the [dependencies](#install-android-dependencies) section.
2. Remove the legacy Android custom `BC` provider and register the updated one.

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
import io.jsonwebtoken.security.SignatureAlgorithms;
import io.jsonwebtoken.security.Keys;
import java.security.Key;

// We need a signing key, so we'll create one just for this example. Usually
// the key would be read from your application configuration instead.
SecretKey key = SignatureAlgorithms.HS256.keyBuilder().build();

String jws = Jwts.builder().setSubject("Joe").signWith(key).compact();
```

How easy was that!?

In this case, we are:
 
 1. *building* a JWT that will have the 
[registered claim](https://tools.ietf.org/html/rfc7519#section-4.1) `sub` (subject) set to `Joe`. We are then
 2. *signing* the JWT using a key suitable for the HMAC-SHA-256 algorithm.  Finally, we are
 3. *compacting* it into its final `String` form.  A signed JWT is called a 'JWS'.

The resultant `jws` String looks like this:

```
eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJKb2UifQ.1KP0SsvENi7Uz1oQc07aXTL7kpQG5jBNIybqr60AlD4
```

Now let's verify the JWT (you should always discard JWTs that don't match an expected signature):

```java
assert Jwts.parserBuilder().verifyWith(key).build().parseClaimsJws(jws).getPayload().getSubject().equals("Joe");
```

There are two things going on here. The `key` from before is being used to verify the signature of the JWT. If it 
fails to verify the JWT, a `SignatureException` (which extends from `JwtException`) is thrown. Assuming the JWT is 
verified, we parse out the claims and assert that that subject is set to `Joe`.  You have to love code one-liners 
that pack a punch!

> **Note**
> 
> **Type-safe JWTs:** To get a type-safe `Claims` JWT result, call the `parseClaimsJws` method (since there are many
similar methods available). You will get an `UnsupportedJwtException` if you parse your JWT with wrong method.

But what if parsing or signature validation failed?  You can catch `JwtException` and react accordingly:

```java
try {

    Jwts.parserBuilder().verifyWith(key).build().parseClaimsJws(compactJws);

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
2. Call builder methods to [add header parameters](#jwt-header-builder) and `payload` [content](#jwt-content) or [claims](#jwt-claims) as desired.
3. Optionally call `signWith` or `encryptWith` methods if you want to digitally sign or encrypt the JWT, respectively.
4. Call the `compact()` method to produce the resulting compact JWT string.

For example:

```java
String jwt = Jwts.builder()                     // (1)
        
    .setSubject("Bob")                          // (2) JSON Claims, or
    //.setContent(aByteArray, "text/plain")     //     any byte[] content, with media type
        
    //.signWith(signingKey)                     // (3) if signing
    //.encryptWith(encryptionAlg, keyAlg, key)  //     if encrypting
        
    .compact();                                 // (4)
```

* Either `byte[]` content may be specified (via `setContent`) _or_ JSON claims 
(such as `setSubject` and other claims methods, or via `setClaims`), but not both.
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
#### Header Builder

The easiest and recommended way to set one or more JWT header parameters (name/value pairs) is to call 
`JwtBuilder` `setHeader` with `Jwts.headerBuilder()`. For example:

```java
String jwt = Jwts.builder()
        
    .setHeader(Jwts.headerBuilder()   // <----
        .setContentType("text/plain")
        .setKeyId("aKeyId")
        .put("someName", "anyValue")
        .putAll(anotherMap)
        // ... etc ...
    )    
    // ... etc ...
    .compact();
```

In addition to type-safe setter methods, `Jwts.headerBuilder()` can also support arbitrary name/value pairs via
`put` and `putAll` as shown above.  It can also support automatically calculating
X.509 thumbprints and other builder-style benefits that the other `JwtBuilder` `setHeader`* methods do not support. 
For this reason, `Jwts.headerBuilder()` is the recommended way to set a JWT header and is preferred over the other
approaches listed next.

> **Note**
> 
> **Automatic Headers**: You do not need to set the `alg`, `enc` or `zip` headers - JJWT will set them automatically
> as needed.

<a name="jwt-header-params"></a>
#### Header Parameters

Another way of setting header parameters is to call `JwtBuilder` `setHeaderParam` one or more times as needed:

```java
String jwt = Jwts.builder()

    .setHeaderParam("kid", "myKeyId")
    
    // ... etc ...

```

Each time `setHeaderParam` is called, it simply appends the key-value pair to an internal `Header` instance,
potentially overwriting any existing identically-named key/value pair.

The downside with this approach is that you lose any type-safe setter methods or additional builder utility methods
available on the `Jwts.headerBuilder()` such as `setContentType`,`setKeyId`, `withX509Sha256Thumbprint`, etc.

> **Note**
> 
> **Automatic Headers**: You do not need to set the `alg`, `enc` or `zip` headers - JJWT will set them automatically
> as needed.

<a name="jwt-header-map"></a><a name="jws-create-header-map"></a> <!-- legacy anchors for old links -->
#### Header Map

If you want to specify the entire header at once, and you don't want to use `Jwts.headerBuilder()`, you can use
`JwtBuilder` `setHeader(Map)` method instead:

```java

Map<String,Object> header = getMyHeaderMap(); //implement me

String jwt = Jwts.builder()

    .setHeader(header)
    
    // ... etc ...

```

> **Warning**
> 
> Per standard Java `setter` idioms, `setHeader` is a _full replacement_ operation - it will replace any
> and all existing header name/value pairs.

The downside with this approach is that you lose any type-safe setter methods or additional builder utility methods
available on the `Jwts.headerBuilder()` such as `setContentType`,`setKeyId`, `withX509Sha256Thumbprint`, etc.

> **Note**
> 
> **Automatic Headers**: You do not need to set the `alg`, `enc` or `zip` headers - JJWT will set them automatically
> as needed.

<a name="jwt-payload"></a>
### JWT Payload

A JWT `payload` can be anything at all - anything that can be represented as a byte array, such as text, images, 
documents, and more.  But since a JWT `header` is always JSON, it makes sense that the `payload` could also be JSON,
especially for representing identity claims.

As a result, the `JwtBuilder` supports two distinct payload options:

* `setContent` if you would like the `payload` to be arbitrary byte array content, and
* `setClaims` (and supporting helper methods) if you would like the `payload` to be a JSON Claims `Object`.

Either option may be used, but not both.  Calling both methods will result in a build error.

<a name="jwt-content"></a>
#### Arbitrary Content

You can set the JWT `payload` to be any arbitrary byte array content by using the `JwtBuilder` `setContent` method.
For example:

```java
byte[] content = "Hello World".getBytes(StandardCharsets.UTF_8);

String jwt = Jwts.builder()

    .setContent(content, "text/plain") // <---
    
    // ... etc ...
        
    .build();
```

Notice this particular example of `setContent` uses the two-argument convenience variant:
1. The first argument is the actual byte content to set as the JWT payload
2. The second argument is a String identifier of an IANA Media Type.

The second argument will cause the `JwtBuilder` to automatically set the `cty` (Content Type) header according to the
JWT specification's [recommended compact format](https://datatracker.ietf.org/doc/html/rfc7515#section-4.1.10).

This two-argument variant is typically recommended over the single-argument `setContent(byte[])` method because it
guarantees the JWT recipient can inspect the `cty` header to determine how to convert the `payload` byte array into
a final form that the application can use.

Without setting the `cty` header, the JWT recipient _must_ know via out-of-band (external) information how to process
the byte array, which is usually less convenient and always requires code changes if the content format ever changes.
For these reasons, it is strongly recommended to use the two-argument `setContent` method variant.

<a name="jwt-claims"></a><a name="jws-create-claims"></a> <!-- legacy anchors for old links -->
#### JWT Claims

Instead of a content byte array, a JWT `payload` may contain assertions or claims for a JWT recipient. In 
this case, the `payload` is a 'claims' JSON `Object`, and JJWT supports this with a type-safe `Claims` instance.

<a name="jwt-claims-standard"></a><a name="jws-create-claims-standard"></a> <!-- legacy anchors for old links -->
##### Standard Claims

The `JwtBuilder` provides convenient setter methods for standard registered Claim names defined in the JWT
specification.  They are:

* `setIssuer`: sets the [`iss` (Issuer) Claim](https://tools.ietf.org/html/rfc7519#section-4.1.1)
* `setSubject`: sets the [`sub` (Subject) Claim](https://tools.ietf.org/html/rfc7519#section-4.1.2)
* `setAudience`: sets the [`aud` (Audience) Claim](https://tools.ietf.org/html/rfc7519#section-4.1.3)
* `setExpiration`: sets the [`exp` (Expiration Time) Claim](https://tools.ietf.org/html/rfc7519#section-4.1.4)
* `setNotBefore`: sets the [`nbf` (Not Before) Claim](https://tools.ietf.org/html/rfc7519#section-4.1.5)
* `setIssuedAt`: sets the [`iat` (Issued At) Claim](https://tools.ietf.org/html/rfc7519#section-4.1.6)
* `setId`: sets the [`jti` (JWT ID) Claim](https://tools.ietf.org/html/rfc7519#section-4.1.7)

For example:

```java

String jws = Jwts.builder()

    .setIssuer("me")
    .setSubject("Bob")
    .setAudience("you")
    .setExpiration(expiration) //a java.util.Date
    .setNotBefore(notBefore) //a java.util.Date 
    .setIssuedAt(new Date()) // for example, now
    .setId(UUID.randomUUID()) //just an example id
    
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

Each time `claim` is called, it simply appends the key-value pair to an internal `Claims` instance, potentially
overwriting any existing identically-named key/value pair.

Obviously, you do not need to call `claim` for any [standard claim name](#jws-create-claims-standard), and it is
recommended instead to call the standard respective type-safe setter method as this enhances readability.

<a name="jwt-claims-instance"></a><a name="jws-create-claims-instance"></a> <!-- legacy anchors for old links -->
##### Claims Instance

If you want to specify all claims at once, you can use the `Jwts.claims()` method and build up the claims
with it:

```java

Claims claims = Jwts.claims();

populate(claims); //implement me

String jws = Jwts.builder()

    .setClaims(claims)
    
    // ... etc ...

```

> **Warning**
> 
> Per standard Java `setter` idioms, calling `setClaims` will fully replace all existing claim name/value
pairs with the specified values.  If you want to add (append) claims in bulk, and not fully replace them, use the 
> `JwtBuilder`'s `addClaims` method instead.

<a name="jwt-claims-map"></a><a name="jws-create-claims-map"></a> <!-- legacy anchors for old links -->
##### Claims Map

If you want to specify all claims at once, and you don't want to use `Jwts.claims()`, you can use `JwtBuilder`
`setClaims(Map)` method instead:

```java

Map<String,Object> claims = getMyClaimsMap(); //implement me

String jws = Jwts.builder()

    .setClaims(claims)
    
    // ... etc ...

```

> **Warning**
>
> Per standard Java `setter` idioms, calling `setClaims` will fully replace all existing claim name/value
pairs with the specified values.  If you want to add (append) claims in bulk, and not fully replace them, use the
> `JwtBuilder`'s `addClaims` method instead.

<a name="jwt-compression"></a><a name="jws-create-compression"></a> <!-- legacy anchors for old links -->
### JWT Compression

If your JWT payload is large (contains a lot of data), you might want to compress the JWT to reduce its size.  Note 
that this is *not* a standard feature for all JWTs - only JWEs - and is not likely to be supported by other JWT 
libraries for non-JWE tokens.  JJWT supports compression for both JWSs and JWEs, however.

Please see the main [Compression](#compression) section to see how to compress and decompress JWTs.

<a name="jwt-read"></a>
## Reading a JWT

You read (parse) a JWT as follows:

1. Use the `Jwts.parserBuilder()` method to create a `JwtParserBuilder` instance.
2. Optionally call `setKeyLocator`, `verifyWith` or `decryptWith` methods if you expect to parse [signed](#jws) or [encrypted](#jwe) JWTs.
3. Call the `build()` method on the `JwtParserBuilder` to create and return a thread-safe `JwtParser`.
4. Call one of the various `parse*` methods with your compact JWT string, depending on the type of JWT you expect.
5. Wrap the `parse*` call in a try/catch block in case parsing, signature verification, or decryption fails.

For example:

```java
Jwt<?,?> jwt;

try {
    jwt = Jwts.parserBuilder() // (1)
        
    .setKeyLocator(keyLocator) // (2) dynamically locate signing or encryption keys    
    //.verifyWith(key)         //     a static key used to verify all signed JWTs
    //.decryptWith(key)        //     a static key used to decrypt all encrypted JWTs
        
    .build()                   // (3)
        
    .parse(compact);           // (4) or parseClaimsJws, parseClaimsJwe, parseContentJws, etc
    
    // we can safely trust the JWT
     
catch (JwtException ex) {      // (5)
    
    // we *cannot* use the JWT as intended by its creator
}
```

> **Note**
> 
> **Type-safe JWTs:** If you are certain your parser will only ever encounter a specific kind of JWT (for example, you only 
> ever use signed JWTs with `Claims` payloads, or encrypted JWTs with `byte[]` content payloads, etc), you can call the 
> associated typesafe `parseClaimsJws`, `parseClaimsJwe`, (etc) method variant instead of the generic `parse` method. 
> 
> These `parse*` methods will return the type-safe JWT you are expecting, for example, a `Jws<Claims>` or `Jwe<byte[]>` 
> instead of a generic `Jwt<?,?>` instance.

<a name="jwt-read-key"></a>
### Parsing Key

If the JWT parsed is a JWS or JWE, a key will be necessary to verify the signature or decrypt it.  If a JWS and 
signature verification fails, or if a JWE and decryption fails, the JWT cannot be safely trusted and should be 
discarded. 

So which key do we use?

* If parsing a JWS and the JWS was signed with a `SecretKey`, the same `SecretKey` should be specified on the 
  `JwtParserBuilder`.  For example:

  ```java
  Jwts.parserBuilder()
      
    .verifyWith(secretKey) // <----
    
    .build()
    .parseClaimsJws(jwsString);
  ```
* If parsing a JWS and the JWS was signed with a `PrivateKey`, that key's corresponding `PublicKey` (not the 
  `PrivateKey`) should be specified on the `JwtParserBuilder`.  For example:

  ```java
  Jwts.parserBuilder()
      
    .verifyWith(publicKey) // <---- publicKey, not privateKey
    
    .build()
    .parseClaimsJws(jwsString);
  ```
* If parsing a JWE and the JWE was encrypted with direct encryption using a `SecretKey`, the same `SecretKey` should be 
  specified on the `JwtParserBuilder`. For example:

  ```java
  Jwts.parserBuilder()
      
    .decryptWith(secretKey) // <----
    
    .build()
    .parseClaimsJwe(jweString);
  ```
* If parsing a JWE and the JWE was encrypted with a key algorithm using with a `PublicKey`, that key's corresponding 
  `PrivateKey` (not the `PublicKey`) should be specified on the `JwtParserBuilder`.  For example:

  ```java
  Jwts.parserBuilder()
      
    .decryptWith(privateKey) // <---- privateKey, not publicKey
    
    .build()
    .parseClaimsJwe(jweString);
  ```
  
If you don't know which key should be used before parsing, you will need to configure a parsing `KeyLocator` instead.

<a name="jwt-read-key-locator"></a>
### Parsing Key Locator

But you might have noticed something - what if your application doesn't use just a single `SecretKey` or `KeyPair`? What
if JWSs and JWEs can be created with different `SecretKey`s or public/private keys, or a combination of both?  How do 
you know which key to specify if you can't inspect the JWT first?

In these cases, you can't call the `JwtParserBuilder`'s `verifyWith` or `decryptWith` methods with a single key - 
instead, you'll need a Key Locator.  Please see the [Key Lookup](#key-locator) section to see how to dynamically 
obtain different keys when parsing JWSs or JWEs.

<a name="jwt-read-claims"></a><a name="jws-read-claims"></a> <!-- legacy anchor for old links -->
### Claim Assertions

You can enforce that the JWT you are parsing conforms to expectations that you require and are important for your
application.

For example, let's say that you require that the JWT you are parsing has a specific `sub` (subject) value,
otherwise you may not trust the token.  You can do that by using one of the various `require`* methods on the
`JwtParserBuilder`:

```java
try {
    Jwts.parserBuilder().requireSubject("jsmith")/* ... etc ... */.build().parse(s);
} catch (InvalidClaimException ice) {
    // the sub field was missing or did not have a 'jsmith' value
}
```

If it is important to react to a missing vs an incorrect value, instead of catching `InvalidClaimException`,
you can catch either `MissingClaimException` or `IncorrectClaimException`:

```java
try {
    Jwts.parserBuilder().requireSubject("jsmith")/* ... etc ... */.build().parse(s);
} catch(MissingClaimException mce) {
    // the parsed JWT did not have the sub field
} catch(IncorrectClaimException ice) {
    // the parsed JWT had a sub field, but its value was not equal to 'jsmith'
}
```

You can also require custom fields by using the `require(fieldName, requiredFieldValue)` method - for example:

```java
try {
    Jwts.parserBuilder().require("myfield", "myRequiredValue")/* ... etc ... */.build().parse(s);
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
`setAllowedClockSkewSeconds`. For example:

```java
long seconds = 3 * 60; //3 minutes

Jwts.parserBuilder()
    
    .setAllowedClockSkewSeconds(seconds) // <----
    
    // ... etc ...
    .build()
    .parse(jwt);
```
This ensures that clock differences between the machines can be ignored. Two or three minutes should be more than
enough; it would be fairly strange if a production machine's clock was more than 5 minutes difference from most
atomic clocks around the world.

<a name="jwt-read-clock-custom"></a><a name="jws-read-clock-custom"></a> <!-- legacy anchor for old links -->
#### Custom Clock Support

If the above `setAllowedClockSkewSeconds` isn't sufficient for your needs, the timestamps created
during parsing for timestamp comparisons can be obtained via a custom time source.  Call the `JwtParserBuilder`'s 
`setClock` method with an implementation of the `io.jsonwebtoken.Clock` interface.  For example:

 ```java
Clock clock = new MyClock();

Jwts.parserBuilder().setClock(myClock) //... etc ...
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

The JWT specification identifies 12 standard signature algorithms - 3 secret key algorithms and 9 asymmetric
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

<sup><b>1</b>. Requires Java 11 or a compatible JCA Provider (like BouncyCastle) in the runtime classpath.</sup>

These are all represented as constants in the `io.jsonwebtoken.security.SignatureAlgorithms` utility class.

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

<a name="jws-key-create"></a>
#### Creating Safe Keys

If you don't want to think about bit length requirements or just want to make your life easier, JJWT has
provided convenient builder classes that can generate sufficiently secure keys for any given
JWT signature algorithm you might want to use.

<a name="jws-key-create-secret"></a>
##### Secret Keys

If you want to generate a sufficiently strong `SecretKey` for use with the JWT HMAC-SHA algorithms, use the respective 
algorithm's `keyBuilder()` method:

```java
SecretKey key = SignatureAlgorithms.HS256.keyBuilder().build(); //or HS384.keyBuilder() or HS512.keyBuilder()
```

Under the hood, JJWT uses the JCA default provider's `KeyGenerator` to create a secure-random key with the correct 
minimum length for the given algorithm.

If you want to specify a specific JCA `Provider` or `SecureRandom` to use during key generation, you may specify those
as builder arguments. For example:

```java
SecretKey key = SignatureAlgorithms.HS256.keyBuilder().setProvider(aProvider).setRandom(aSecureRandom).build();
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
algorithms, use an algorithm's respective `keyPairBuilder()` method:

```java
KeyPair keyPair = SignatureAlgorithms.RS256.keyPairBuilder().build(); //or RS384, RS512, PS256, PS384, PS512, ES256, ES384, ES512
```

Once you've generated a `KeyPair`, you can use the private key (`keyPair.getPrivate()`) to create a JWS and the 
public key (`keyPair.getPublic()`) to parse/verify a JWS.

> **Note**
> 
> The `PS256`, `PS384`, and `PS512` algorithms require JDK 11 or a compatible JCA Provider
> (like BouncyCastle) in the runtime classpath.**  If you are using JDK 10 or earlier and you want to use them, see
> the [Installation](#Installation) section to see how to enable BouncyCastle.  All other algorithms are natively
> supported by the JDK.

<a name="jws-create"></a>
### Creating a JWS

You create a JWS as follows:

1. Use the `Jwts.builder()` method to create a `JwtBuilder` instance.  
2. Call `JwtBuilder` methods to add header parameters and `payload` content or claims as desired.
3. Specify the `SecretKey` or asymmetric `PrivateKey` you want to use to sign the JWT.
4. Finally, call the `compact()` method to compact and sign, producing the final jws.

For example:

```java
String jws = Jwts.builder() // (1)

    .setSubject("Bob")      // (2) 

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
> You cannot sign JWTs with `PublicKey`s as this is always insecure.** JJWT will reject any specified
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

   .signWith(privateKey, SignatureAlgorithms.RS512) // <---
   
   .compact();

```

This is allowed because the JWT specification allows any RSA algorithm strength for any RSA key >= 2048 bits.  JJWT just
prefers `RS512` for keys >= 4096 bits, followed by `RS384` for keys >= 3072 bits and finally `RS256` for keys >= 2048
bits.

**In all cases however, regardless of your chosen algorithms, JJWT will assert that the specified key is allowed to be 
used for that algorithm when possible according to the JWT specification requirements.**

<a name="jws-create-compression"></a>
#### JWS Compression

If your JWT claims set is large (contains a lot of data), and you are certain that JJWT will also be the same library 
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

1. Use the `Jwts.parserBuilder()` method to create a `JwtParserBuilder` instance.  
2. Specify the `SecretKey` or asymmetric `PublicKey` you want to use to verify the JWS signature.<sup>1</sup>
3. Call the `build()` method on the `JwtParserBuilder` to return a thread-safe `JwtParser`.
4. Finally, call the `parseClaimsJws(String)` method with your jws `String`, producing the original JWS.
5. The entire call is wrapped in a try/catch block in case parsing or signature validation fails.  We'll cover
   exceptions and causes for failure later.

<sup>1. If you don't know which key to use at the time of parsing, you can look up the key using a Key `Locator` 
which [we'll cover later](#jws-read-key-locator).</sup>

For example:

```java
Jws<Claims> jws;

try {
    jws = Jwts.parserBuilder()  // (1)
    .verifyWith(key)            // (2)
    .build()                    // (3)
    .parseClaimsJws(jwsString); // (4)
    
    // we can safely trust the JWT
     
catch (JwtException ex) {       // (5)
    
    // we *cannot* use the JWT as intended by its creator
}
```

> **Note**
>
> **Type-safe JWTs:** If you are expecting a JWS with a claims `payload`, call `JwtParser`'s `parseClaimsJws` method
for the convenience of a type-safe result.

<a name="jws-read-key"></a>
#### Verification Key

The most important thing to do when reading a JWS is to specify the key used to verify the JWS's
cryptographic signature.  If signature verification fails, the JWT cannot be safely trusted and should be 
discarded.

So which key do we use for verification?

* If the jws was signed with a `SecretKey`, the same `SecretKey` should be specified on the `JwtParserBuilder`.  
For example:

  ```java
  Jwts.parserBuilder()
      
    .verifyWith(secretKey) // <----
    
    .build()
    .parseClaimsJws(jwsString);
  ```
* If the jws was signed with a `PrivateKey`, that key's corresponding `PublicKey` (not the `PrivateKey`) should be 
  specified on the `JwtParserBuilder`.  For example:

  ```java
  Jwts.parserBuilder()
      
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

These two properties - confidentiality and integrity - assure us that an encrypted JWT contains a `paylaod` that 
no-one else can see, _nor_ has anyone changed or altered the data in transit.

Encryption and confidentiality seem somewhat obvious: if you encrypt a message, it is confidential by the notion that
random 3rd parties cannot make sense of the encrypted message. But some might be surprised to know that **_general 
encryption does _not_ guarantee that someone hasn't tampered/altered an encrypted message in transit_**.  Most of us 
assume that if a message can be decrypted, then the message would be authentic and unchanged - after all, if you can 
decrypt it, it must not have been tampered with, right? Because if it was changed, decryption would surely fail, right?

Unfortunately, this is not actually guaranteed in all cryptographic ciphers. There are certain attack vectors where 
it is possible to change an encrypted payload (called 'ciphertext'), and still have the message recipient be able to 
successfully decrypt the (modified) payload.  In these cases, the ciphertext integrity was not maintained - a 
malicious 3rd party could intercept a message and change the payload content, even if they don't understand what is 
inside the payload, and the message recipient could never know.

To combat this, there is a category of encryption algorithms that both ensure confidentiality _and_ integrity of the 
ciphertext data.  These types of algorithms are called 
[Authenticated Encryption](https://en.wikipedia.org/wiki/Authenticated_encryption) algorithms.

As a result, to ensure JWTs do not suffer from this problem, the JWE RFC specifications require that any encryption
algorithm used to encrypt a JWT _MUST_ be an Authenticated Encryption algorithm.  JWT users can be sufficiently 
confident their encrypted JWTs maintain the properties of both confidentiality and integrity.

<a name="jwe-enc"></a>
### JWE Encryption Algorithms

The JWT specification defines 6 standard Authenticated Encryption algorithms used to encrypt a JWT `payload`:

| Identifier | Required Key Bit Length | Encryption Algorithm |
| --- | --- | --- |
| <code>A128CBC&#8209;HS256</code> | 256 | [AES_128_CBC_HMAC_SHA_256](https://datatracker.ietf.org/doc/html/rfc7518#section-5.2.3) authenticated encryption algorithm |
| `A192CBC-HS384` | 384 | [AES_192_CBC_HMAC_SHA_384](https://datatracker.ietf.org/doc/html/rfc7518#section-5.2.4) authenticated encryption algorithm |
| `A256CBC-HS512` | 512 | [AES_256_CBC_HMAC_SHA_512](https://datatracker.ietf.org/doc/html/rfc7518#section-5.2.5) authenticated encryption algorithm |
| `A128GCM` | 128 | AES GCM using 128-bit key<sup><b>1</b></sup> |
| `A192GCM` | 192 | AES GCM using 192-bit key<sup><b>1</b></sup> |
| `A256GCM` | 256 | AES GCM using 256-bit key<sup><b>1</b></sup> |

These are all represented as constants in the `io.jsonwebtoken.security.EncryptionAlgorithms` utility class as 
implementations of the `io.jsonwebtoken.security.AeadAlgorithm` interface.

As shown in the table above, each algorithm requires a key of sufficient length.  The JWT specification
[RFC 7518, Sections 5.2.3 through 5.3](https://datatracker.ietf.org/doc/html/rfc7518#section-5.2.3)
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

Yes, they definitely can, and the JWT specifications do support them, albeit in a roundabout way:  those other 
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

That is, JWT encryption can be thought of a two-step process, shown in the following pseudocode:

```groovy

Key algorithmKey = getKeyManagementAlgorithmKey(); // PublicKey, SecretKey, or PasswordKey

SecretKey contentEncryptionKey = keyManagementAlgorithm.produceEncryptionKey(algorithmKey); // 1

byte[] ciphertext = encryptionAlgorithm.encrypt(payload, contentEncryptionKey);             // 2
```

Steps:

1. Use the `algorithmKey` to produce the actual key that will be used to encrypt the payload.  The JWT specifications
   call this result the 'Content Encryption Key'.
2. Take the resulting Content Encryption Key and use it directly with the Authenticated Encryption algorithm to
   actually encrypt the JWT `payload`.

So why the indirection?  Why not just use any `PublicKey`, `SecretKey` or `PasswordKey` to encrypt the `payload`
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
algorithm has been proven to be a great way to increase security exposure through many more secure algorithms while 
also still resulting in very fast and secure output.  This is after all how TLS (for https encryption) works - 
two parties can use more complex cryptography (like RSA or Elliptic Curve) to negotiate a small, fast encryption key. 
This is done during the 'TLS handshake' to produce a 'session key'.

So the JWT specifications work much in the same way: one key from any number of various algorithm types can be used
to produce a final symmetric key, and that symmetric key is used to encrypt the JWT `payload`.

<a name="jwe-alg-standard"></a>
#### JWE Standard Key Management Algorithms

The JWT specification defines 17 standard Key Management Algorithms used to produce the `payload` encryption key:

| Identifier | Key Management Algorithm |
| --- | --- |   
| `RSA1_5` | RSAES-PKCS1-v1_5 |
| `RSA-OAEP` | RSAES OAEP using default parameters |
| `RSA-OAEP-256` | RSAES OAEP using SHA-256 and MGF1 with SHA-256 |
| `A128KW` | AES Key Wrap with default initial value using 128-bit key |
| `A192KW` | AES Key Wrap with default initial value using 192-bit key |
| `A256KW` | AES Key Wrap with default initial value using 256-bit key |
| `dir` | Direct use of a shared symmetric key as the CEK |
| `ECDH-ES` | Elliptic Curve Diffie-Hellman Ephemeral Static key agreement using Concat KDF |
| `ECDH-ES+A128KW` | ECDH-ES using Concat KDF and CEK wrapped with "A128KW" |
| `ECDH-ES+A192KW` | ECDH-ES using Concat KDF and CEK wrapped with "A192KW" |
| `ECDH-ES+A256KW` | ECDH-ES using Concat KDF and CEK wrapped with "A256KW" |
| `A128GCMKW` | Key wrapping with AES GCM using 128-bit key<sup><b>3</b></sup> |
| `A192GCMKW` | Key wrapping with AES GCM using 192-bit key<sup><b>3</b></sup> |
| `A256GCMKW` | Key wrapping with AES GCM using 256-bit key<sup><b>3</b></sup> |
| `PBES2-HS256+A128KW` | PBES2 with HMAC SHA-256 and "A128KW" wrapping<sup><b>3</b></sup> |
| `PBES2-HS384+A192KW` | PBES2 with HMAC SHA-384 and "A192KW" wrapping<sup><b>3</b></sup> |
| <code>PBES2&#8209;HS512&plus;A256KW</code> | PBES2 with HMAC SHA-512 and "A256KW" wrapping<sup><b>3</b></sup> |

<sup><b>3</b>. Requires Java 8 or a compatible JCA Provider (like BouncyCastle) in the runtime classpath.</sup>

These are all represented in the `io.jsonwebtoken.security.KeyAlgorithms` utility class as implementations of
the `io.jsonwebtoken.security.KeyAlgorithm` interface.

<a name="jwe-create"></a>
### Creating a JWE

Now that we know the difference between a JWE Encryption Algorithm and a JWE Key Management Algorithm, how do we use
them to encrypt a JWT?

You create an encrypted JWT (called a 'JWE') as follows:

1. Use the `Jwts.builder()` method to create a `JwtBuilder` instance.
2. Call `JwtBuilder` methods to add [header](#jws-create-header) parameters and [claims](#jws-create-claims) as desired.
3. Call the `encryptWith` method, specifying the Encryption Algorithm, Key Algorithm, and Key you want to use.
4. Finally, call the `compact()` method to compact and encrypt, producing the final jwe.

For example:

```java
String jwe = Jwts.builder()                              // (1)

    .setSubject("Bob")                                   // (2) 

    .encryptWith(encryptionAlgorithm, key, keyAlgorithm) // (3)
     
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

1. Use the `Jwts.parserBuilder()` method to create a `JwtParserBuilder` instance.
2. Tell the `JwtParserBuilder` which key to use during decryption.  That can be either:
   * A statically-configured `SecretKey`, `PasswordKey`, or asymmetric `PublicKey`, or,
   * A dynamic [Key Locator](#key-locator) used to look up a key at runtime based on the JWE being parsed.
3. Call the `JwtParserBuilder`'s `build()` method to create a thread-safe `JwtParser`.
4. Parse the jwe string with the `JwtParser`'s `parseClaimsJwe` or `parseContentJwe` method.
5. Wrap the entire call is in a try/catch block in case decryption or integrity verification fails.

For example:

```java
Jwe<Claims> jwe;

try {
    jwe = Jwts.parserBuilder()  // (1)
        
    .decryptWith(key)           // (2) static key, or
    //.setKeyLocator(keyLocator)       dynamic key lookup
        
    .build()                    // (3)
    .parseClaimsJwe(jweString); // (4) or parseContentJwe(jweString);
    
    // we can safely trust the JWT
     
catch (JwtException ex) {       // (5)
    
    // we *cannot* use the JWT as intended by its creator
}
```

> **Note**
> 
> **Expected Payload Type:** 
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
  Jwts.parserBuilder()
      
    .decryptWith(secretKey) // <----
    
    .build()
    .parseClaimsJws(jwsString);
  ```
* If the jwe was encrypted using a key produced by a Password-based key derivation `KeyAlgorithm`, the same 
  `PasswordKey` must be specified on the `JwtParserBuilder`. For example:

  ```java
  Jwts.parserBuilder()
      
    .decryptWith(passwordKey) // <---- a `PasswordKey` instance
    
    .build()
    .parseClaimsJws(jwsString);
  ```
* If the jwe was encrypted with a key produced by an asymmetric `KeyAlgorithm`, the corresponding `PrivateKey` (not 
  the `PublicKey`) must be specified on the `JwtParserBuilder`.  For example:

  ```java
  Jwts.parserBuilder()
      
    .decryptWith(privateKey) // <---- a `PrivateKey`, not a `PublicKey`
    
    .build()
    .parseClaimsJws(jwsString);
  ```

<a name="jwe-key-locator"></a>
#### Decryption Key Locator

What if your application doesn't use just a single `SecretKey` or `KeyPair`? What
if JWEs can be created with different `SecretKey`s, `PasswordKey`s or public/private keys, or a combination of all of 
them?  How do you know which key to specify if you can't inspect the JWT first?

In these cases, you can't call the `JwtParserBuilder`'s `decryptWith` method with a single key - instead, you'll need
to use a Key `Locator`.  Please see the [Key Lookup](#key-locator) section to see how to dynamically obtain different 
keys when parsing JWSs or JWEs.

<a name="jwe-read-decompression"></a>
#### JWE Decompression

If a JWE is compressed using the `DEF` ([DEFLATE](https://www.rfc-editor.org/rfc/rfc1951)) or `GZIP` 
([GZIP](https://www.rfc-editor.org/rfc/rfc1952.html)) compression algorithms, it will automatically be decompressed
after decryption, and there is nothing you need to configure.

If, however, a custom compression algorithm was used to compress the JWE, you will need to tell the
`JwtParserBuilder` how to resolve your `CompressionCodec` to decompress the JWT.

Please see the [Compression](#compression) section below to see how to decompress JWTs during parsing.

<a name="key-locator"></a>
## Key Lookup

It is common in many applications to receive JWTs that can be encrypted or signed by different cryptographic keys.  For
example, maybe a JWT created to assert a specific user identity uses a Key specific to that exact user. Or perhaps JWTs
specific to a particular customer all use that customer's Key.  Or maybe your application creates JWTs that are 
encrypted with a key specific to your application for your own use (e.g. a user session token).

In all of these and similar scenarios, you won't know which key was used to sign or encrypt a JWT until the JWT is 
received, at parse time, so you can't 'hard code' any verification or decryption key using the `JwtParserBuilder`'s
`verifyWith` or `decryptWith` methods.  Those are only to be used when the same key is used to verify or decrypt
*all* JWSs or JWEs, which won't work for dynamically signed or encrypted JWTs.

<a name="key-locator-custom"></a>
### Custom Key Locator

If you need to support dynamic key resolution when encountering JWTs, you'll need to implement 
the `Locator<Key>` interface and specify an instance on the `JwtParserBuilder` via the `setKeyLocator` method. For 
example:

```java
Locator<Key> keyLocator = getMyKeyLocator();

Jwts.parserBuilder()

    .setKeyLocator(keyLocator) // <----
    
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

<a name="key-locator-custom-strategy"></a>
#### Key Locator Strategy

What data might you inspect to determine how to lookup a signature verification or decryption key?

The JWT specifications' preferred approach is to set a `kid` (Key ID) header value when the JWT is being created, 
for example:

```java

Key key = getSigningKey(); // or getEncryptionKey() for JWE

String keyId = getKeyId(key); //any mechanism you have to associate a key with an ID is fine

String jws = Jwts.builder()
        
    .setHeader(Jwts.headerBuilder().setKeyId(keyId))     // <--- add `kid` header
    
    .signWith(key)                                       // for JWS
    //.encryptWith(encryptionAlg, keyManagementAlg, key) // for JWE
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
> :information_source: **Simpler Lookup**:
> If possible, try to keep the key lookup strategy the same between JWSs and JWEs (i.e. using 
> only `locate(ProtectedHeader<?>)`), preferably using only
> the `kid` (Key ID) header value or perhaps a public key thumbprint.  You will find the implementation is much 
> simpler and easier to maintain over time, and also creates smaller headers for compact transmission.

<a name="key-locator-custom-retvals"></a>
#### Key Locator Return Values

Regardless of which implementation strategy you choose, remember to return the appropriate type of key depending
on the type of JWS or JWE algorithm used.  That is:

* for JWS:
  * For HMAC-based signature algorithms, the returned verification key should be a `SecretKey`, and, 
  * For asymmetric signature algorithms, the returned verification key should be a `PublicKey` (not a `PrivateKey`).
* for JWE:
  * For JWE direct encryption, the returned decryption key should be a `SecretKey`.
  * For password-based key derivation algorithms, the returned decryption key should be a `PasswordKey`.
  * For asymmetric key management algorithms, the returned decryption key should be a `PrivateKey` (not a `PublicKey`).

<a name="compression"></a>
## Compression

**The JWT specification only standardizes this feature for JWEs (Encrypted JWTs) and not Unprotected JWTs or JWSs 
(Signed JWTs), however JJWT supports all three**.  If you are positive that a JWT you create with JJWT will 
_also_ be parsed with JJWT, you can use this feature with any JWT, otherwise it is best to only use it for JWEs.  

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
   
   .compressWith(CompressionCodecs.DEFLATE) // or CompressionCodecs.GZIP
   
   // .. etc ...
```

If you use the `DEFLATE` or `GZIP` Compression Codecs - that's it, you're done.  You don't have to do anything during 
parsing or configure the `JwtParserBuilder` for compression - JJWT will automatically decompress the payload as 
expected.

<a name="compression-custom"></a>
### Custom Compression Codec

If the default `DEFLATE` or `GZIP` compression codecs are not suitable for your needs, you can create your own 
`CompressionCodec` implementation(s).

Just as you would with the default codecs, you may specify that you want a JWT compressed by calling the `JwtBuilder`'s
`compressWith` method, supplying your custom implementation instance.   When you call `compressWith`, the JWT `payload`
will be compressed with your algorithm, and the 
[`zip` (Compression Algorithm)](https://datatracker.ietf.org/doc/html/rfc7516#section-4.1.3) 
header will automatically be set to the value returned by your codec's `getId()` method as specified in the JWT
specification.

However, the `JwtParser` needs to be aware of this custom codec as well, so it can use it while parsing. You do this 
by calling the `JwtParserBuilder`'s `addCompressionCodecs` method.  For example:

```java
CompressionCodec myCodec = new MyCompressionCodec();

Jwts.parserBuilder()

    .addCompressionCodecs(Collections.of(myCodec)) // <----
    
    // .. etc ...
```

This adds additional `CompressionCodec` implementations to the parser's overall total set of supported codecs (which
already includes the `DEFLATE` and `GZIP` codecs by default).

The parser will then automatically check to see if the JWT `zip` header has been set to see if a compression codec
algorithm has been used to compress the JWT.  If set, the parser will automatically look up your `CompressionCodec` by
its `getId()` value, and use it to decompress the JWT.

<a name="compression-custom-locator"></a>
### Compression Codec Locator

If for some reason the default `addCompressionCodecs` method and lookup-by-id behavior already supported by the 
`JwtParserBuilder` is not sufficient for your needs, you can implement your own `Locator<CompressionCodec>` to look 
up the codec.

Typically, a `Locator<CompressionCodec>` implementation will inspect the `zip` header to find out what algorithm was
used and then return a codec instance that supports that algorithm.  For example:

```java
public class MyCompressionCodecLocator implements Locator<CompressionCodec> {
        
    @Override
    public CompressionCodec locate(Header<?> header) {
        
        String id = header.getCompressionAlgorithm(); // 'zip' header
            
        CompressionCodec codec = getCompressionCodec(id); //implement me
            
        return codec;
    }
}
```

Your custom `Locator<CompressionCodec>` can then inspect any other header as necessary.

You then provide your custom `Locator<CompressionCodec>` to the `JwtParserBuilder` as follows:

```java
Locator<CompressionCodec> myCodecLocator = new MyCompressionCodecLocator();

Jwts.parserBuilder()

    .setCompressionCodecLocator(myCodecLocator) // <----
    
    // .. etc ...
```

Again, this is only necessary if the JWT-standard `zip` header lookup default behavior already supported by the 
`JwtParser` is not sufficient.

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

    .serializeToJsonWith(serializer)
    
    // ... etc ...
```

When reading a JWT:

```java
Deserializer<Map<String,?>> deserializer = getMyDeserializer(); //implement me

Jwts.parserBuilder()

    .deserializeJsonWith(deserializer)
    
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

    .serializeToJsonWith(new JacksonSerializer(objectMapper))
    
    // ... etc ...
```

and the `JacksonDeserializer` using your `ObjectMapper` on the `JwtParserBuilder`:

```java
ObjectMapper objectMapper = getMyObjectMapper(); //implement me

Jwts.parserBuilder()

    .deserializeJsonWith(new JacksonDeserializer(objectMapper))
    
    // ... etc ...
```

<a name="json-jackson-custom-types"></a>
#### Parsing of Custom Claim Types

By default JJWT will only convert simple claim types: String, Date, Long, Integer, Short and Byte.  If you need to deserialize other types you can configure the `JacksonDeserializer` by passing a `Map` of claim names to types in through a constructor. For example:

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
Jwts.parserBuilder()

    .deserializeJsonWith(new JacksonDeserializer(Maps.of("user", User.class).build())) // <-----

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

    .serializeToJsonWith(new GsonSerializer(gson))
    
    // ... etc ...
```

and the `GsonDeserializer` using your `Gson` instance on the `JwtParser`:

```java
Gson gson = getGson(); //implement me

Jwts.parser()

    .deserializeJsonWith(new GsonDeserializer(gson))
    
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

A base64-encoded key is still sensitive information and must
be kept as secret and as safe as the original thing you got the bytes from (e.g. a Java `PrivateKey` or `SecretKey` 
instance).

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
`base64UrlEncodeWith` method to set the encoder:

```java
Encoder<byte[], String> base64UrlEncoder = getMyBase64UrlEncoder(); //implement me

String jws = Jwts.builder()

    .base64UrlEncodeWith(base64UrlEncoder)
    
    // ... etc ...
```

and the `JwtParserBuilder`'s `base64UrlDecodeWith` method to set the decoder:

```java
Decoder<String, byte[]> base64UrlDecoder = getMyBase64UrlDecoder(); //implement me

Jwts.parserBuilder()

    .base64UrlDecodeWith(base64UrlEncoder)
    
    // ... etc ...
```

## Learn More

- [JSON Web Token for Java and Android](https://stormpath.com/blog/jjwt-how-it-works-why/)
- [How to Create and Verify JWTs in Java](https://stormpath.com/blog/jwt-java-create-verify/)
- [Where to Store Your JWTs - Cookies vs HTML5 Web Storage](https://stormpath.com/blog/where-to-store-your-jwts-cookies-vs-html5-web-storage/)
- [Use JWT the Right Way!](https://stormpath.com/blog/jwt-the-right-way/)
- [Token Authentication for Java Applications](https://stormpath.com/blog/token-auth-for-java/)
- [JJWT Changelog](CHANGELOG.md)

## Author

Maintained by Les Hazlewood &amp; the community :heart:

<a name="license"></a>
## License

This project is open-source via the [Apache 2.0 License](http://www.apache.org/licenses/LICENSE-2.0).
