[![Build Status](https://travis-ci.org/jwtk/jjwt.svg?branch=master)](https://travis-ci.org/jwtk/jjwt)
[![Coverage Status](https://coveralls.io/repos/github/jwtk/jjwt/badge.svg?branch=master)](https://coveralls.io/github/jwtk/jjwt?branch=master)

## Java JWT: JSON Web Token for Java and Android

JJWT aims to be the easiest to use and understand library for creating and verifying JSON Web Tokens (JWTs) on the JVM
and Android.

JJWT is a pure Java implementation based 
exclusively on the [JWT](https://tools.ietf.org/html/rfc7519), 
[JWS](https://tools.ietf.org/html/rfc7515), [JWE](https://tools.ietf.org/html/rfc7516), 
[JWK](https://tools.ietf.org/html/rfc7517) and [JWA](https://tools.ietf.org/html/rfc7518) RFC specifications and 
open source under the terms of the [Apache 2.0 License](http://www.apache.org/licenses/LICENSE-2.0).

The library was created by [Okta's](http://www.okta.com) Senior Architect, [Les Hazlewood](https://github.com/lhazlewood)
and is supported and maintained by a [community](https://github.com/jwtk/jjwt/graphs/contributors) of contributors.

[Okta](https://developer.okta.com/) is a complete authentication and user management API for developers.

We've also added some convenience extensions that are not part of the specification, such as JWT compression and claim 
enforcement.

## Table of Contents

* [Features](#features)
  * [Currently Unsupported Features](#features-unsupported)
* [What is a JSON Web Token?](#overview)
* [Installation](#install)
  * [JDK Projects](#install-jdk)
    * [Maven](#install-jdk-maven)
    * [Gradle](#install-jdk-gradle)
  * [Android Projects](#install-android)
    * [Dependencies](#install-android-dependencies)
    * [Proguard Exclusions](#install-android-proguard)
  * [Understanding JJWT Dependencies](#install-understandingdependencies)
* [Quickstart](#quickstart)
* [Signed JWTs](#jws)
  * [Signature Algorithm Keys](#jws-key)
    * [HMAC-SHA](#jws-key-hmacsha)
    * [RSA](#jws-key-rsa)
    * [Elliptic Curve](#jws-key-ecdsa)
    * [Creating Safe Keys](#jws-key-create)
      * [Secret Keys](#jws-key-create-secret)
      * [Asymetric Keys](#jws-key-create-asym)
  * [Create a JWS](#jws-create)
    * [Header](#jws-create-header)
      * [Instance](#jws-create-header-instance)
      * [Map](#jws-create-header-map)
    * [Claims](#jws-create-claims)
      * [Standard Claims](#jws-create-claims-standard)
      * [Custom Claims](#jws-create-claims-custom)
      * [Claims Instance](#jws-create-claims-instance)
      * [Claims Map](#jws-create-claims-map)
    * [Signing Key](#jws-create-key)
      * [Signature Algorithm Override](#jws-create-key-algoverride)
    * [Compression](#jws-create-compression)
  * [Read a JWS](#jws-read)
    * [Verification Key](#jws-read-key)
      * [Find the Verification Key at Runtime](#jws-read-key-resolver)
    * [Claims Assertions](#jws-read-claims)
    * [Accounting for Clock Skew](#jws-read-clock)
      * [Custom Clock](#jws-read-clock-custom)
    * [Decompression](#jws-read-decompression)
    <!-- * [Error Handling](#jws-read-errors) -->
* [Compression](#compression)
  * [Custom Compression Codec](#compression-custom)
* [JSON Processor](#json)
  * [Custom JSON Processor](#json-custom)
  * [Jackson ObjectMapper](#json-jackson)
* [Base64 Codec](#base64)
  * [Custom Base64 Codec](#base64-custom)

<a name="features"></a>
## Features

 * Fully functional on all JDKs and Android
 * Automatic security best practices and assertions
 * Easy to learn and read API
 * Convenient and readable [fluent](http://en.wikipedia.org/wiki/Fluent_interface) interfaces, great for IDE auto-completion to write code quickly
 * Fully RFC specification compliant on all implemented functionality, tested against RFC-specified test vectors
 * Stable implementation with enforced 100% test code coverage.  Literally every single method, statement and 
   conditional branch variant in the entire codebase is tested and required to pass on every build.
 * Creating, parsing and verifying digitally signed compact JWTs (aka JWSs) with all standard JWS algorithms:
    * HS256: HMAC using SHA-256
    * HS384: HMAC using SHA-384
    * HS512: HMAC using SHA-512
    * ES256: ECDSA using P-256 and SHA-256
    * ES384: ECDSA using P-384 and SHA-384
    * ES512: ECDSA using P-521 and SHA-512
    * RS256: RSASSA-PKCS-v1_5 using SHA-256
    * RS384: RSASSA-PKCS-v1_5 using SHA-384
    * RS512: RSASSA-PKCS-v1_5 using SHA-512
    * PS256: RSASSA-PSS using SHA-256 and MGF1 with SHA-256<sup>1</sup>
    * PS384: RSASSA-PSS using SHA-384 and MGF1 with SHA-384<sup>1</sup>
    * PS512: RSASSA-PSS using SHA-512 and MGF1 with SHA-512<sup>1</sup>
    
     <sup>1. Requires JDK 11 or a compatible JCA Provider (like BouncyCastle) in the runtime classpath.</sup>
 * Convenience enhancements beyond the specification such as
    * Body compression for any large JWT, not just JWEs
    * Claims assertions (requiring specific values)
    * Claim POJO marshaling and unmarshaling when using a compatible JSON parser (e.g. Jackson) 
    * Secure Key generation based on desired JWA algorithms
    * and more...
    
<a name="features-unsupported"></a>
### Currently Unsupported Features

* [Non-compact](https://tools.ietf.org/html/rfc7515#section-7.2) serialization and parsing.
* JWE (Encryption for JWT)

These features will be implemented in a future release.  Community contributions are welcome!

<a name="overview"></a>
## What is a JSON Web Token?

Don't know what a JSON Web Token is? Read on. Otherwise, jump on down to the [Installation](#Installation) section.

JWT is a means of transmitting information between two parties in a compact, verifiable form.

The bits of information encoded in the body of a JWT are called `claims`. The expanded form of the JWT is in a JSON format, so each `claim` is a key in the JSON object.
 
JWTs can be cryptographically signed (making it a [JWS](https://tools.ietf.org/html/rfc7515)) or encrypted (making it a [JWE](https://tools.ietf.org/html/rfc7516)).

This adds a powerful layer of verifiability to the user of JWTs. The receiver has a high degree of confidence that the JWT has not been tampered with by verifying the signature, for instance.

The compact representation of a signed JWT is a string that has three parts, each separated by a `.`:

```
eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJKb2UifQ.ipevRNuRP6HflG8cFKnmUPtypruRC4fb1DWtoLL62SY
```

Each part is [Base64URL](https://en.wikipedia.org/wiki/Base64)-encoded. The first part is the header, which at a 
minimum needs to specify the algorithm used to sign the JWT. The second part is the body. This part has all 
the claims of this JWT encoded in it. The final part is the signature. It's computed by passing a combination of 
the header and body through the algorithm specified in the header.
 
If you pass the first two parts through a base 64 url decoder, you'll get the following (formatting added for 
clarity):

`header`
```
{
  "alg": "HS256"
}
```

`body`
```
{
  "sub": "Joe"
}
```

In this case, the information we have is that the HMAC using SHA-256 algorithm was used to sign the JWT. And, the 
body has a single claim, `sub` with value `Joe`.

There are a number of standard claims, called [Registered Claims](https://tools.ietf.org/html/rfc7519#section-4.1), 
in the specification and `sub` (for subject) is one of them.

To compute the signature, you need a secret key to sign it. We'll cover keys and algorithms later.

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
    <version>0.10.5</version>
</dependency>
<dependency>
    <groupId>io.jsonwebtoken</groupId>
    <artifactId>jjwt-impl</artifactId>
    <version>0.10.5</version>
    <scope>runtime</scope>
</dependency>
<dependency>
    <groupId>io.jsonwebtoken</groupId>
    <artifactId>jjwt-jackson</artifactId>
    <version>0.10.5</version>
    <scope>runtime</scope>
</dependency>
<!-- Uncomment this next dependency if you want to use RSASSA-PSS (PS256, PS384, PS512) algorithms:
<dependency>
    <groupId>org.bouncycastle</groupId>
    <artifactId>bcprov-jdk15on</artifactId>
    <version>1.60</version>
    <scope>runtime</scope>
</dependency>
-->

```

<a name="install-jdk-gradle"></a>
#### Gradle

```groovy
dependencies {
    compile 'io.jsonwebtoken:jjwt-api:0.10.5'
    runtime 'io.jsonwebtoken:jjwt-impl:0.10.5',
            // Uncomment the next line if you want to use RSASSA-PSS (PS256, PS384, PS512) algorithms:
            //'org.bouncycastle:bcprov-jdk15on:1.60',
            'io.jsonwebtoken:jjwt-jackson:0.10.5'
}
```

<a name="install-android"></a>
### Android Projects

Android projects will want to define the following dependencies and Proguard exclusions:

<a name="install-android-dependencies"></a>
#### Dependencies

Add the dependencies to your project:

```groovy
dependencies {
    api 'io.jsonwebtoken:jjwt-api:0.10.5'
    runtimeOnly 'io.jsonwebtoken:jjwt-impl:0.10.5' 
    runtimeOnly('io.jsonwebtoken:jjwt-orgjson:0.10.5') {
        exclude group: 'org.json', module: 'json' //provided by Android natively
    }
    // Uncomment the next line if you want to use RSASSA-PSS (PS256, PS384, PS512) algorithms:
    //runtimeOnly 'org.bouncycastle:bcprov-jdk15on:1.60'
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

<a name="install-understandingdependencies"></a>
### Understanding JJWT Dependencies

Notice the above dependency declarations all have only one compile-time dependency and the rest are declared as 
_runtime_ dependencies.

This is because JJWT is designed so you only depend on the APIs that are explicitly designed for you to use in
your applications and all other internal implementation details - that can change without warning - are relegated to
runtime-only dependencies.  This is an extremely important point if you want to ensure stable JJWT usage and
upgrades over time:

**JJWT guarantees semantic versioning compatibility for all of its artifacts _except_ the `jjwt-impl` .jar.  No such 
guarantee is made for the `jjwt-impl` .jar and internal changes in that .jar can happen at any time.  Never add the 
`jjwt-impl` .jar to your project with `compile` scope - always declare it with `runtime` scope.**

This is done to benefit you: great care goes into curating the `jjwt-api` .jar and ensuring it contains what you need
and remains backwards compatible as much as is possible so you can depend on that safely with compile scope.  The 
runtime `jjwt-impl` .jar strategy affords the JJWT developers the flexibility to change the internal packages and 
implementations whenever and however necessary.  This helps us implement features, fix bugs, and ship new releases to 
you more quickly and efficiently.

<a name="quickstart"></a>
## Quickstart

Most complexity is hidden behind a convenient and readable builder-based [fluent interface](http://en.wikipedia.org/wiki/Fluent_interface), great for relying on IDE auto-completion to write code quickly.  Here's an example:

```java
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import java.security.Key;

// We need a signing key, so we'll create one just for this example. Usually
// the key would be read from your application configuration instead.
Key key = Keys.secretKeyFor(SignatureAlgorithm.HS256);

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
assert Jwts.parser().setSigningKey(key).parseClaimsJws(jws).getBody().getSubject().equals("Joe");
```

**NOTE: Ensure you call the `parseClaimsJws` method** (since there are many similar methods available). You will get an `UnsupportedJwtException` if you parse your JWT with wrong method.

There are two things going on here. The `key` from before is being used to validate the signature of the JWT. If it 
fails to verify the JWT, a `SignatureException` (which extends from `JwtException`) is thrown. Assuming the JWT is 
validated, we parse out the claims and assert that that subject is set to `Joe`.

You have to love code one-liners that pack a punch!

But what if parsing or signature validation failed?  You can catch `JwtException` and react accordingly:

```java
try {

    Jwts.parser().setSigningKey(key).parseClaimsJws(compactJws);

    //OK, we can trust this JWT

} catch (JwtException e) {

    //don't trust the JWT!
}
```

<a name="jws"></a>
## Signed JWTs

The JWT specification provides for the ability to 
[cryptographically _sign_](https://en.wikipedia.org/wiki/Digital_signature) a JWT.  Signing a JWT:
 
1. guarantees the JWT was created by someone we know (it is authentic) as well as
2. guarantees that no-one has manipulated or changed the JWT after it was created (its integrity is maintained).

These two properties - authenticity and integrity - assure us that a JWT contains information we can trust.  If a 
JWT fails authenticity or integrity checks, we should always reject that JWT because we can't trust it.

So how is a JWT signed?  Let's walk through it with some easy-to-read pseudocode:

1. Assume we have a JWT with a JSON header and body (aka 'Claims') as follows:
  
   **header**
   ```
   {
     "alg": "HS256"
   }
   ```
   
   **body**
   ```
   {
     "sub": "Joe"
   }
   ```
   
2. Remove all unnecessary whitespace in the JSON:
   
   ```groovy
   String header = '{"alg":"HS256"}'
   String claims = '{"sub":"Joe"}'
   ```
   
3. Get the UTF-8 bytes and Base64URL-encode each:
   
   ```groovy
   String encodedHeader = base64URLEncode( header.getBytes("UTF-8") )
   String encodedClaims = base64URLEncode( claims.getBytes("UTF-8") )
   ```
   
4. Concatenate the encoded header and claims with a period character between them:

   ```groovy
   String concatenated = encodedHeader + '.' + encodedClaims
   ```
   
5.  Use a sufficiently-strong cryptographic secret or private key, along with a signing algorithm of your choice
    (we'll use HMAC-SHA-256 here), and sign the concatenated string:
    
    ```groovy
    Key key = getMySecretKey()
    byte[] signature = hmacSha256( concatenated, key )
    ```
    
6. Because signatures are always byte arrays, Base64URL-encode the signature and append a period character '.' and it 
   to the concatenated string:
   
   ```groovy
   String jws = concatenated + '.' + base64URLEncode( signature )
   ```
 
 
And there you have it, the final `jws` String looks like this:
 
```
eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJKb2UifQ.1KP0SsvENi7Uz1oQc07aXTL7kpQG5jBNIybqr60AlD4
```

This is called a 'JWS' - short for _signed_ JWT.

Of course, no one would want to do this manually in code, and worse, if you get anything wrong, you could cause 
security problems or weaknesses.  As a result, JJWT was created to handle all of this for you: JJWT completely 
automates both the creation of JWSs as well as the parsing and verification of JWSs for you.

But before we dig in to showing you how to create a JWS using JJWT, let's briefly discuss Signature Algorithms and 
Keys, specifically as they relate to the JWT specifications.  Understanding them is critical to being able to create a 
JWS properly.

<a name="jws-key"></a>
### Signature Algorithms Keys

The JWT specification identifies 12 standard signature algorithms - 3 secret key algorithms and 9 asymmetric 
key algorithms - identified by the following names:

* `HS256`: HMAC using SHA-256
* `HS384`: HMAC using SHA-384
* `HS512`: HMAC using SHA-512
* `ES256`: ECDSA using P-256 and SHA-256
* `ES384`: ECDSA using P-384 and SHA-384
* `ES512`: ECDSA using P-521 and SHA-512
* `RS256`: RSASSA-PKCS-v1_5 using SHA-256
* `RS384`: RSASSA-PKCS-v1_5 using SHA-384
* `RS512`: RSASSA-PKCS-v1_5 using SHA-512
* `PS256`: RSASSA-PSS using SHA-256 and MGF1 with SHA-256
* `PS384`: RSASSA-PSS using SHA-384 and MGF1 with SHA-384
* `PS512`: RSASSA-PSS using SHA-512 and MGF1 with SHA-512

These are all represented in the `io.jsonwebtoken.SignatureAlgorithm` enum.

What's really important about these algorithms - other than their security properties - is that the JWT specification
[RFC 7518, Sections 3.2 through 3.5](https://tools.ietf.org/html/rfc7518#section-3)
_requires_ (mandates) that you MUST use keys that are sufficiently strong for a chosen algorithm.

This means that JJWT - a specification-compliant library - will also enforce that you use sufficiently strong keys
for the algorithms you choose.  If you provide a weak key for a given algorithm, JJWT will reject it and throw an
exception.

This is not because we want to make your life difficult, we promise! The reason why the JWT specification, and 
consequently JJWT, mandates key lengths is that the security model of a particular algorithm can completely break 
down if you don't adhere to the mandatory key properties of the algorithm, effectively having no security at all.  No 
one wants completely insecure JWTs, right?  Neither would we.

So what are the requirements?

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
Anything smaller than this (such as 1024 bits) will be rejected with an `InvalidKeyException`.

That said, in keeping with best practices and increasing key lengths for security longevity, JJWT 
recoommends that you use:

* at least 2048 bit keys with `RS256` and `PS256`
* at least 3072 bit keys with `RS384` and `PS384`
* at least 4096 bit keys with `RS512` and `PS512`

These are only JJWT suggestions and not requirements. JJWT only enforces JWT specification requirements and
for any RSA key, the requirement is the RSA key (modulus) length in bits MUST be >= 2048 bits.

<a name="jws-key-ecdsa"></a>
#### Elliptic Curve

JWT Elliptic Curve signature algorithms `ES256`, `ES384`, and `ES512` all require a minimum key length
(aka an Elliptic Curve order bit length) that is _at least_ as many bits as the algorithm signature's individual 
`R` and `S` components per [RFC 7512 Section 3.4](https://tools.ietf.org/html/rfc7518#section-3.4).  This means:

* `ES256` requires that you use a private key that is at least 256 bits (32 bytes) long.
  
* `ES384` requires that you use a private key that is at least 384 bits (48 bytes) long.

* `ES512` requires that you use a private key that is at least 512 bits (64 bytes) long.

<a name="jws-key-create"></a>
#### Creating Safe Keys

If you don't want to think about bit length requirements or just want to make your life easier, JJWT has
provided the `io.jsonwebtoken.security.Keys` utility class that can generate sufficiently secure keys for any given
JWT signature algorithm you might want to use.

<a name="jws-key-create-secret"></a>
##### Secret Keys

If you want to generate a sufficiently strong `SecretKey` for use with the JWT HMAC-SHA algorithms, use the 
`Keys.secretKeyFor(SignatureAlgorithm)` helper method:

```java
SecretKey key = Keys.secretKeyFor(SignatureAlgorithm.HS256); //or HS384 or HS512
```

Under the hood, JJWT uses the JCA provider's `KeyGenerator` to create a secure-random key with the correct minimum
length for the given algorithm.

If you have an existing HMAC SHA `SecretKey`'s 
[encoded byte array](https://docs.oracle.com/javase/8/docs/api/java/security/Key.html#getEncoded--), you can use 
the `Keys.hmacShaKeyFor` helper method.  For example:

```java
byte[] keyBytes = getSigningKeyFromApplicationConfiguration();
SecretKey key = Keys.hmacShaKeyFor(keyBytes);
```

<a name="jws-key-create-asym"></a>
##### Asymmetric Keys

If you want to generate sufficiently strong Elliptic Curve or RSA asymmetric key pairs for use with JWT ECDSA or RSA
algorithms, use the `Keys.keyPairFor(SignatureAlgorithm)` helper method:

```java
KeyPair keyPair = Keys.keyPairFor(SignatureAlgorithm.RS256); //or RS384, RS512, PS256, PS384, PS512, ES256, ES384, ES512
```

You use the private key (`keyPair.getPrivate()`) to create a JWS and the public key (`keyPair.getPublic()`) to 
parse/verify a JWS.

**NOTE: The `PS256`, `PS384`, and `PS512` algorithms require JDK 11 or a compatible JCA Provider 
(like BouncyCastle) in the runtime classpath.**  If you are using JDK 10 or earlier and you want to use them, see 
the [Installation](#Installation) section to see how to enable BouncyCastle.  All other algorithms are natively 
supported by the JDK.

<a name="jws-create"></a>
### Creating a JWS

You create a JWS as follows:

1. Use the `Jwts.builder()` method to create a `JwtBuilder` instance.  
2. Call `JwtBuilder` methods to add header parameters and claims as desired.
3. Specify the `SecretKey` or asymmetric `PrivateKey` you want to use to sign the JWT.
4. Finally, call the `compact()` method to compact and sign, producing the final jws.

For example:

```java
String jws = Jwts.builder() // (1)

    .setSubject("Bob")      // (2) 

    .signWith(key)          // (3)
     
    .compact();             // (4)
```

<a name="jws-create-header"></a>
#### Header Parameters

A JWT Header provides metadata about the contents, format and cryptographic operations relevant to the JWT's Claims.

If you need to set one or more JWT header parameters, such as the `kid` 
[(Key ID) header parameter](https://tools.ietf.org/html/rfc7515#section-4.1.4), you can simply call
`JwtBuilder` `setHeaderParameter` one or more times as needed:

```java
String jws = Jwts.builder()

    .setHeaderParameter("kid", "myKeyId")
    
    // ... etc ...

```

Each time `setHeaderParameter` is called, it simply appends the key-value pair to an internal `Header` instance, 
potentially overwriting any existing identically-named key/value pair.

**NOTE**: You do not need to set the `alg` or `zip` header parameters as JJWT will set them automatically
depending on the signature algorithm or compression algorithm used.

<a name="jws-create-header-instance"></a>
##### Header Instance

If you want to specify the entire header at once, you can use the `Jwts.header()` method and build up the header
paramters with it:

```java

Header header = Jwts.header();

populate(header); //implement me

String jws = Jwts.builder()

    .setHeader(header)
    
    // ... etc ...

```

**NOTE**: Calling `setHeader` will overwrite any existing header name/value pairs with the same names that might have 
already been set. In all cases however, JJWT will still set (and overwrite) any `alg` and `zip` headers regardless 
if those are in the specified `header` object or not.

<a name="jws-create-header-map"></a>
##### Header Map

If you want to specify the entire header at once and you don't want to use `Jwts.header()`, you can use `JwtBuilder` 
`setHeader(Map)` method instead:

```java

Map<String,Object> header = getMyHeaderMap(); //implement me

String jws = Jwts.builder()

    .setHeader(header)
    
    // ... etc ...

```


**NOTE**: Calling `setHeader` will overwrite any existing header name/value pairs with the same names that might have 
already been set. In all cases however, JJWT will still set (and overwrite) any `alg` and `zip` headers regardless 
if those are in the specified `header` object or not.

<a name="jws-create-claims"></a>
#### Claims

Claims are a JWT's 'body' and contain the information that the JWT creator wishes to present to the JWT recipient(s).

<a name="jws-create-claims-standard"></a>
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

<a name="jws-create-claims-custom"></a>
##### Custom Claims

If you need to set one or more custom claims that don't match the standard setter method claims shown above, you
can simply call `JwtBuilder` `claim` one or more times as needed:

```java
String jws = Jwts.builder()

    .claim("hello", "world")
    
    // ... etc ...

```

Each time `claim` is called, it simply appends the key-value pair to an internal `Claims` instance, potentially 
overwriting any existing identically-named key/value pair.

Obviously, you do not need to call `claim` for any [standard claim name](#jws-create-claims-standard) and it is 
recommended instead to call the standard respective setter method as this enhances readability.

<a name="jws-create-claims-instance"></a>
###### Claims Instance

If you want to specify all claims at once, you can use the `Jwts.claims()` method and build up the claims
with it:

```java

Claims claims = Jwts.claims();

populate(claims); //implement me

String jws = Jwts.builder()

    .setClaims(claims)
    
    // ... etc ...

```

**NOTE**: Calling `setClaims` will overwrite any existing claim name/value pairs with the same names that might have 
already been set.

<a name="jws-create-claims-map"></a>
###### Claims Map

If you want to specify all claims at once and you don't want to use `Jwts.claims()`, you can use `JwtBuilder` 
`setClaims(Map)` method instead:

```java

Map<String,Object> claims = getMyClaimsMap(); //implement me

String jws = Jwts.builder()

    .setClaims(claims)
    
    // ... etc ...

```

**NOTE**: Calling `setClaims` will overwrite any existing claim name/value pairs with the same names that might have 
already been set.

<a name="jws-create-key"></a>
#### Signing Key

It is recommended that you specify the signing key by calling call the `JwtBuilder`'s `signWith` method and let JJWT
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

Similarly, if you called `signWith` with an RSA `PrivateKey` that was 4096 bits long, JJWT will use the `R512`
algorithm and automatically set the `alg` header to `RS512`.

The same selection logic applies for Elliptic Curve `PrivateKey`s.

**NOTE: You cannot sign JWTs with `PublicKey`s as this is always insecure.** JJWT will reject any specified
`PublicKey` for signing with an `InvalidKeyException`. 

<a name="jws-create-key-algoverride"></a>
##### SignatureAlgorithm Override

In some specific cases, you might want to override JJWT's default selected algorithm for a given key.

For example, if you have an RSA `PrivateKey` that is 2048 bits, JJWT would automatically choose the `RS256` algorithm.
If you wanted to use `RS384` or `RS512` instead, you could manually specify it with the overloaded `signWith` method
that accepts the `SignatureAlgorithm` as an additional parameter:

```java

   .signWith(privateKey, SignatureAlgorithm.RS512) // <---
   
   .compact();

```

This is allowed because the JWT specification allows any RSA algorithm strength for any RSA key >= 2048 bits.  JJWT just
prefers `RS512` for keys >= 4096 bits, followed by `RS384` for keys >= 3072 bits and finally `RS256` for keys >= 2048
bits.

**In all cases however, regardless of your chosen algorithms, JJWT will assert that the specified key is allowed to be 
used for that algorithm according to the JWT specification requirements.**

<a name="jws-create-compression"></a>
#### JWS Compression

If your JWT claims set is large (contains a lot of data), and you are certain that JJWT will also be the same library 
that reads/parses your JWS, you might want to compress the JWS to reduce its size.  Note that this is
*not* a standard feature for JWS and is not likely to be supported by other JWT libraries.

Please see the main [Compression](#compression) section to see how to compress and decompress JWTs.

<a name="jws-read"></a>
### Reading a JWS

You read (parse) a JWS as follows:

1. Use the `Jwts.parser()` method to create a `JwtParser` instance.  
2. Specify the `SecretKey` or asymmetric `PublicKey` you want to use to verify the JWS signature.<sup>1</sup>
3. Finally, call the `parseClaimsJws(String)` method with your jws `String`, producing the original JWS.
4. The entire call is wrapped in a try/catch block in case parsing or signature validation fails.  We'll cover
   exceptions and causes for failure later.

<sup>1. If you don't know which key to use at the time of parsing, you can look up the key using a `SigningKeyResolver` 
which [we'll cover later](#jws-read-key-resolver).</sup>

For example:

```java
Jws<Claims> jws;

try {
    jws = Jwts.parser()         // (1)
    .setSigningKey(key)         // (2)
    .parseClaimsJws(jwsString); // (3)
    
    // we can safely trust the JWT
     
catch (JwtException ex) {       // (4)
    
    // we *cannot* use the JWT as intended by its creator
}
```

**NOTE: If you expecting a JWS, always call `JwtParser`'s `parseClaimsJws` method** (and not one of the other similar methods 
available) as this guarantees the correct security model for parsing signed JWTs.

<a name="jws-read-key"></a>
#### Verification Key

The most important thing to do when reading a JWS is to specify the key to use to verify the JWS's
cryptographic signature.  If signature verification fails, the JWT cannot be safely trusted and should be 
discarded.

So which key do we use for verification?

* If the jws was signed with a `SecretKey`, the same `SecretKey` should be specified on the `JwtParser`.  For example:

  ```java
  Jwts.parser()
      
    .setSigningKey(secretKey) // <----
    
    .parseClaimsJws(jwsString);
  ```
* If the jws was signed with a `PrivateKey`, that key's corresponding `PublicKey` (not the `PrivateKey`) should be 
  specified on the `JwtParser`.  For example:

  ```java
  Jwts.parser()
      
    .setSigningKey(publicKey) // <---- publicKey, not privateKey
    
    .parseClaimsJws(jwsString);
  ```
  
But you might have noticed something - what if your application doesn't use just a single SecretKey or KeyPair? What
if JWSs can be created with different `SecretKey`s or public/private keys, or a combination of both?  How do you
know which key to specify if you can't inspect the JWT first?

In these cases, you can't call the `JwtParser`'s `setSigningKey` method with a single key - instead, you'll need
to use a `SigningKeyResolver`, covered next.

<a name="jws-read-key-resolver"></a>
##### Signing Key Resolver

If your application expects JWSs that can be signed with different keys, you won't call the `setSigningKey` method.
Instead, you'll need to implement the 
`SigningKeyResolver` interface and specify an instance on the `JwtParser` via the `setSigningKeyResolver` method.  
For example:

```java
SigningKeyResolver signingKeyResolver = getMySigningKeyResolver();

Jwts.parser()

    .setSigningKeyResolver(signingKeyResolver) // <----
    
    .parseClaimsJws(jwsString);
```

You can simplify things a little by extending from the `SigningKeyResolverAdapter` and implementing the 
`resolveSigningKey(JwsHeader, Claims)` method.  For example:

```java
public class MySigningKeyResolver extends SigningKeyResolverAdapter {
    
    @Override
    public Key resolveSigningKey(JwsHeader jwsHeader, Claims claims) {
        // implement me
    }
}
```

The `JwtParser` will invoke the `resolveSigningKey` method after parsing the JWS JSON, but _before verifying the
jws signature_.  This allows you to inspect the `JwsHeader` and `Claims` arguments for any information that can
help you look up the `Key` to use for verifying _that specific jws_.  This is very powerful for applications
with more complex security models that might use different keys at different times or for different users or customers.

Which data might you inspect?

The JWT specification's supported way to do this is to set a `kid` (Key ID) field in the JWS header when the JWS is 
being created, for example:

```java

Key signingKey = getSigningKey();

String keyId = getKeyId(signingKey); //any mechanism you have to associate a key with an ID is fine

String jws = Jwts.builder()
    
    .setHeaderParam(JwsHeader.KEY_ID, keyId) // 1
    
    .signWith(signingKey)                    // 2
    
    .compact();
```

Then during parsing, your `SigningKeyResolver` can inspect the `JwsHeader` to get the `kid` and then use that value
to look up the key from somewhere, like a database.  For example:

```java
public class MySigningKeyResolver extends SigningKeyResolverAdapter {
    
    @Override
    public Key resolveSigningKey(JwsHeader jwsHeader, Claims claims) {
        
        //inspect the header or claims, lookup and return the signing key
        
        String keyId = jwsHeader.getKeyId(); //or any other field that you need to inspect
        
        Key key = lookupVerificationKey(keyId); //implement me
        
        return key;
    }
}
```

Note that inspecting the `jwsHeader.getKeyId()` is just the most common approach to look up a key - you could 
inspect any number of header fields or claims to determine how to lookup the verification key.  It is all based on 
how the JWS was created.

Finally remember that for HMAC algorithms, the returned verification key should be a `SecretKey`, and for asymmetric 
algorithms, the key returned should be a `PublicKey` (not a `PrivateKey`).

<a name="jws-read-claims"></a>
#### Claim Assertions

You can enforce that the JWS you are parsing conforms to expectations that you require and are important for your 
application.

For example, let's say that you require that the JWS you are parsing has a specific `sub` (subject) value,
otherwise you may not trust the token.  You can do that by using one of the various `require`* methods on the 
`JwtParser`:

```java
try {
    Jwts.parser().requireSubject("jsmith").setSigningKey(key).parseClaimsJws(s);
} catch(InvalidClaimException ice) {
    // the sub field was missing or did not have a 'jsmith' value
}
```

If it is important to react to a missing vs an incorrect value, instead of catching `InvalidClaimException`, 
you can catch either `MissingClaimException` or `IncorrectClaimException`:

```java
try {
    Jwts.parser().requireSubject("jsmith").setSigningKey(key).parseClaimsJws(s);
} catch(MissingClaimException mce) {
    // the parsed JWT did not have the sub field
} catch(IncorrectClaimException ice) {
    // the parsed JWT had a sub field, but its value was not equal to 'jsmith'
}
```

You can also require custom fields by using the `require(fieldName, requiredFieldValue)` method - for example:

```java
try {
    Jwts.parser().require("myfield", "myRequiredValue").setSigningKey(key).parseClaimsJws(s);
} catch(InvalidClaimException ice) {
    // the 'myfield' field was missing or did not have a 'myRequiredValue' value
}
```
(or, again, you could catch either `MissingClaimException` or `IncorrectClaimException` instead).

Please see the `JwtParser` class and/or JavaDoc for a full list of the various `require`* methods you may use for claims
assertions.

<a name="jws-read-clock"></a>
#### Accounting for Clock Skew

When parsing a JWT, you might find that `exp` or `nbf` claim assertions fail (throw exceptions) because the clock on 
the parsing machine is not perfectly in sync with the clock on the machine that created the JWT.  This can cause 
obvious problems since `exp` and `nbf` are time-based assertions, and clock times need to be reliably in sync for shared
assertions.

You can account for these differences (usually no more than a few minutes) when parsing using the `JwtParser`'s
 `setAllowedClockSkewSeconds`. For example:

```java
long seconds = 3 * 60; //3 minutes

Jwts.parser()
    
    .setAllowedClockSkewSeconds(seconds) // <----
    
    // ... etc ...
    .parseClaimsJws(jwt);
```
This ensures that clock differences between the machines can be ignored. Two or three minutes should be more than 
enough; it would be fairly strange if a production machine's clock was more than 5 minutes difference from most 
atomic clocks around the world.

<a name="jws-read-clock-custom"></a>
##### Custom Clock Support

If the above `setAllowedClockSkewSeconds` isn't sufficient for your needs, the timestamps created
during parsing for timestamp comparisons can be obtained via a custom time source.  Call the `JwtParser`'s `setClock`
 method with an implementation of the `io.jsonwebtoken.Clock` interface.  For example:
 
 ```java
Clock clock = new MyClock();

Jwts.parser().setClock(myClock) //... etc ...
``` 

The `JwtParser`'s default `Clock` implementation simply returns `new Date()` to reflect the time when parsing occurs, 
as most would expect.  However, supplying your own clock could be useful, especially when writing test cases to 
guarantee deterministic behavior.

<a name="jws-read-decompression"></a>
#### JWS Decompression

If you used JJWT to compress a JWS and you used a custom compression algorithm, you will need to tell the `JwtParser`
how to resolve your `CompressionCodec` to decompress the JWT.

Please see the [Compression](#compression) section below to see how to decompress JWTs during parsing.

<!-- TODO: ## Encrypted JWTs -->

<a name="compression"></a>
## Compression

**The JWT specification only standardizes this feature for JWEs (Encrypted JWTs) and not JWSs (Signed JWTs), however
JJWT supports both**.  If you are positive that a JWS you create with JJWT will _also_ be parsed with JJWT, you 
can use this feature with JWSs, otherwise it is best to only use it for JWEs.  

If a JWT's Claims set is sufficiently large - that is, it contains a lot of name/value pairs, or individual values are 
very large or verbose - you can reduce the size of the created JWS by compressing the claims body.

This might be important to you if the resulting JWS is used in a URL for example, since URLs are best kept under 
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
parsing or configure the `JwtParser` for compression - JJWT will automatically decompress the body as expected.

<a name="compression-custom"></a>
### Custom Compression Codec

If however, you used your own custom compression codec when creating the JWT (via `JwtBuilder` `compressWith`), then
you need to supply the codec to the `JwtParser` using the `setCompressionCodecResolver` method.  For example:

```java
CompressionCodecResolver ccr = new MyCompressionCodecResolver();

Jwts.parser()

    .setCompressionCodecResolver(ccr) // <----
    
    // .. etc ...
```

Typically a `CompressionCodecResolver` implementation will inspect the `zip` header to find out what algorithm was
used and then return a codec instance that supports that algorithm.  For example:

```java
public class MyCompressionCodecResolver implements CompressionCodecResolver {
        
    @Override
    public CompressionCodec resolveCompressionCodec(Header header) throws CompressionException {
        
        String alg = header.getCompressionAlgorithm();
            
        CompressionCodec codec = getCompressionCodec(alg); //implement me
            
        return codec;
    }
}
```

<a name="json"></a>
## JSON Support

A `JwtBuilder` will serialize the `Header` and `Claims` maps (and potentially any Java objects they 
contain) to JSON with a `Serializer<Map<String, ?>>` instance.  Similarly, a `JwtParser` will 
deserialize JSON into the `Header` and `Claims` using a `Deserializer<Map<String, ?>>` instance.

If you don't explicitly configure a `JwtBuilder`'s `Serializer` or a `JwtParser`'s `Deserializer`, JJWT will 
automatically attempt to discover and use the following JSON implementations if found in the runtime classpath.  
They are checked in order, and the first one found is used:

1. Jackson: This will automatically be used if you specify `io.jsonwebtoken:jjwt-jackson` as a project runtime 
   dependency.  Jackson supports POJOs as claims with full marshaling/unmarshaling as necessary.
   
2. JSON-Java (`org.json`): This will be used automatically if you specify `io.jsonwebtoken:jjwt-orgjson` as a 
   project runtime dependency.
   
   **NOTE:** `org.json` APIs are natively enabled in Android environments so this is the recommended JSON processor for 
   Android applications _unless_ you want to use POJOs as claims.  The `org.json` library supports simple 
   Object-to-JSON marshaling, but it *does not* support JSON-to-Object unmarshalling.

**If you want to use POJOs as claim values, use the `io.jsonwebtoken:jjwt-jackson` dependency** (or implement your own
Serializer and Deserializer if desired).  **But beware**, Jackson will force a sizable (> 1 MB) dependency to an 
Android application thus increasing the app download size for mobile users.

<a name="json-custom"></a>
### Custom JSON Processor

If you don't want to use JJWT's runtime dependency approach, or just want to customize how JSON serialization and 
deserialization works, you can implement the `Serializer` and `Deserializer` interfaces and specify instances of
them on the `JwtBuilder` and `JwtParser` respectively.  For example:

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

Jwts.parser()

    .deserializeJsonWith(deserializer)
    
    // ... etc ...
```

<a name="json-jackson"></a>
### Jackson JSON Processor

If you have an application-wide Jackson `ObjectMapper` (as is typically recommended for most applications), you can 
eliminate the overhead of JJWT constructing its own `ObjectMapper` by using yours instead.

You do this by declaring the `io.jsonwebtoken:jjwt-jackson` dependency with **compile** scope (not runtime 
scope which is the typical JJWT default).  That is:

**Maven**

```xml
<dependency>
    <groupId>io.jsonwebtoken</groupId>
    <artifactId>jjwt-jackson</artifactId>
    <version>0.10.5</version>
    <scope>compile</scope> <!-- Not runtime -->
</dependency>
```

**Gradle or Android**

```groovy
dependencies {
    compile 'io.jsonwebtoken:jjwt-jackson:0.10.5'
}
```

And then you can specify the `JacksonSerializer` using your own `ObjectMapper` on the `JwtBuilder`:

```java
ObjectMapper objectMapper = getMyObjectMapper(); //implement me

String jws = Jwts.builder()

    .serializeToJsonWith(new JacksonSerializer(objectMapper))
    
    // ... etc ...
```

and the `JacksonDeserializer` using your `ObjectMapper` on the `JwtParser`:

```java
ObjectMapper objectMapper = getMyObjectMapper(); //implement me

Jwts.parser()

    .deserializeJsonWith(new JacksonDeserializer(objectMapper))
    
    // ... etc ...
```

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

and the `JwtParser`'s `base64UrlDecodeWith` method to set the decoder:

```java
Decoder<String, byte[]> base64UrlDecoder = getMyBase64UrlDecoder(); //implement me

Jwts.parser()

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

Maintained by Les Hazlewood &amp; [Okta](https://okta.com/)

<a name="license"></a>
## License

This project is open-source via the [Apache 2.0 License](http://www.apache.org/licenses/LICENSE-2.0).
