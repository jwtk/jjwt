[![Build Status](https://travis-ci.org/jwtk/jjwt.svg?branch=master)](https://travis-ci.org/jwtk/jjwt)
[![Coverage Status](https://coveralls.io/repos/github/jwtk/jjwt/badge.svg?branch=master)](https://coveralls.io/github/jwtk/jjwt?branch=master)
[![Gitter](https://badges.gitter.im/jwtk/jjwt.svg)](https://gitter.im/jwtk/jjwt?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge)

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
      * [SecretKey Formats](#jws-create-key-secret)
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

<a name="community"></a>
## Community

<a name="help"></a>
### Getting Help

If you have trouble using JJWT, please first read the documentation on this page before asking questions.  We try 
very hard to ensure JJWT's documentation is robust, categorized with a table of contents, and up to date for each release.

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

**If a GitHub Issue is created that does not represent actionable work for JJWT's codebase, it will be promptly closed.**

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

It would be a shame to reject your earnest and genuinely appreciated pull request if it might not not align with the 
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
    <version>0.11.2</version>
</dependency>
<dependency>
    <groupId>io.jsonwebtoken</groupId>
    <artifactId>jjwt-impl</artifactId>
    <version>0.11.2</version>
    <scope>runtime</scope>
</dependency>
<dependency>
    <groupId>io.jsonwebtoken</groupId>
    <artifactId>jjwt-jackson</artifactId> <!-- or jjwt-gson if Gson is preferred -->
    <version>0.11.2</version>
    <scope>runtime</scope>
</dependency>
<!-- Uncomment this next dependency if you are using JDK 10 or earlier and you also want to use 
     RSASSA-PSS (PS256, PS384, PS512) algorithms.  JDK 11 or later does not require it for those algorithms:
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
    compile 'io.jsonwebtoken:jjwt-api:0.11.2'
    runtime 'io.jsonwebtoken:jjwt-impl:0.11.2',
            // Uncomment the next line if you want to use RSASSA-PSS (PS256, PS384, PS512) algorithms:
            //'org.bouncycastle:bcprov-jdk15on:1.60',
            'io.jsonwebtoken:jjwt-jackson:0.11.2' // or 'io.jsonwebtoken:jjwt-gson:0.11.2' for gson
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
    api 'io.jsonwebtoken:jjwt-api:0.11.2'
    runtimeOnly 'io.jsonwebtoken:jjwt-impl:0.11.2' 
    runtimeOnly('io.jsonwebtoken:jjwt-orgjson:0.11.2') {
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
assert Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(jws).getBody().getSubject().equals("Joe");
```

**NOTE: Ensure you call the `parseClaimsJws` method** (since there are many similar methods available). You will get an `UnsupportedJwtException` if you parse your JWT with wrong method.

There are two things going on here. The `key` from before is being used to validate the signature of the JWT. If it 
fails to verify the JWT, a `SignatureException` (which extends from `JwtException`) is thrown. Assuming the JWT is 
validated, we parse out the claims and assert that that subject is set to `Joe`.

You have to love code one-liners that pack a punch!

But what if parsing or signature validation failed?  You can catch `JwtException` and react accordingly:

```java
try {

    Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(compactJws);

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
`JwtBuilder` `setHeaderParam` one or more times as needed:

```java
String jws = Jwts.builder()

    .setHeaderParam("kid", "myKeyId")
    
    // ... etc ...

```

Each time `setHeaderParam` is called, it simply appends the key-value pair to an internal `Header` instance, 
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

Similarly, if you called `signWith` with an RSA `PrivateKey` that was 4096 bits long, JJWT will use the `RS512`
algorithm and automatically set the `alg` header to `RS512`.

The same selection logic applies for Elliptic Curve `PrivateKey`s.

**NOTE: You cannot sign JWTs with `PublicKey`s as this is always insecure.** JJWT will reject any specified
`PublicKey` for signing with an `InvalidKeyException`.

<a name="jws-create-key-secret"></a>
##### SecretKey Formats

If you want to sign a JWS using HMAC-SHA algorithms and you have a secret key `String` or 
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

1. Use the `Jwts.parserBuilder()` method to create a `JwtParserBuilder` instance.  
2. Specify the `SecretKey` or asymmetric `PublicKey` you want to use to verify the JWS signature.<sup>1</sup>
3. Call the `build()` method on the `JwtParserBuilder` to return a thread-safe `JwtParser`.
4. Finally, call the `parseClaimsJws(String)` method with your jws `String`, producing the original JWS.
5. The entire call is wrapped in a try/catch block in case parsing or signature validation fails.  We'll cover
   exceptions and causes for failure later.

<sup>1. If you don't know which key to use at the time of parsing, you can look up the key using a `SigningKeyResolver` 
which [we'll cover later](#jws-read-key-resolver).</sup>

For example:

```java
Jws<Claims> jws;

try {
    jws = Jwts.parserBuilder()  // (1)
    .setSigningKey(key)         // (2)
    .build()                    // (3)
    .parseClaimsJws(jwsString); // (4)
    
    // we can safely trust the JWT
     
catch (JwtException ex) {       // (5)
    
    // we *cannot* use the JWT as intended by its creator
}
```

**NOTE: If you are expecting a JWS, always call `JwtParser`'s `parseClaimsJws` method** (and not one of the other similar methods 
available) as this guarantees the correct security model for parsing signed JWTs.

<a name="jws-read-key"></a>
#### Verification Key

The most important thing to do when reading a JWS is to specify the key to use to verify the JWS's
cryptographic signature.  If signature verification fails, the JWT cannot be safely trusted and should be 
discarded.

So which key do we use for verification?

* If the jws was signed with a `SecretKey`, the same `SecretKey` should be specified on the `JwtParserBuilder`.  For example:

  ```java
  Jwts.parserBuilder()
      
    .setSigningKey(secretKey) // <----
    
    .build()
    .parseClaimsJws(jwsString);
  ```
* If the jws was signed with a `PrivateKey`, that key's corresponding `PublicKey` (not the `PrivateKey`) should be 
  specified on the `JwtParserBuilder`.  For example:

  ```java
  Jwts.parserBuilder()
      
    .setSigningKey(publicKey) // <---- publicKey, not privateKey
    
    .build()
    .parseClaimsJws(jwsString);
  ```
  
But you might have noticed something - what if your application doesn't use just a single SecretKey or KeyPair? What
if JWSs can be created with different `SecretKey`s or public/private keys, or a combination of both?  How do you
know which key to specify if you can't inspect the JWT first?

In these cases, you can't call the `JwtParserBuilder`'s `setSigningKey` method with a single key - instead, you'll need
to use a `SigningKeyResolver`, covered next.

<a name="jws-read-key-resolver"></a>
##### Signing Key Resolver

If your application expects JWSs that can be signed with different keys, you won't call the `setSigningKey` method.
Instead, you'll need to implement the 
`SigningKeyResolver` interface and specify an instance on the `JwtParserBuilder` via the `setSigningKeyResolver` method.  
For example:

```java
SigningKeyResolver signingKeyResolver = getMySigningKeyResolver();

Jwts.parserBuilder()

    .setSigningKeyResolver(signingKeyResolver) // <----
    
    .build()
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
`JwtParserBuilder`:

```java
try {
    Jwts.parserBuilder().requireSubject("jsmith").setSigningKey(key).build().parseClaimsJws(s);
} catch(InvalidClaimException ice) {
    // the sub field was missing or did not have a 'jsmith' value
}
```

If it is important to react to a missing vs an incorrect value, instead of catching `InvalidClaimException`, 
you can catch either `MissingClaimException` or `IncorrectClaimException`:

```java
try {
    Jwts.parserBuilder().requireSubject("jsmith").setSigningKey(key).build().parseClaimsJws(s);
} catch(MissingClaimException mce) {
    // the parsed JWT did not have the sub field
} catch(IncorrectClaimException ice) {
    // the parsed JWT had a sub field, but its value was not equal to 'jsmith'
}
```

You can also require custom fields by using the `require(fieldName, requiredFieldValue)` method - for example:

```java
try {
    Jwts.parserBuilder().require("myfield", "myRequiredValue").setSigningKey(key).build().parseClaimsJws(s);
} catch(InvalidClaimException ice) {
    // the 'myfield' field was missing or did not have a 'myRequiredValue' value
}
```
(or, again, you could catch either `MissingClaimException` or `IncorrectClaimException` instead).

Please see the `JwtParserBuilder` class and/or JavaDoc for a full list of the various `require`* methods you may use for claims
assertions.

<a name="jws-read-clock"></a>
#### Accounting for Clock Skew

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
    .parseClaimsJws(jwt);
```
This ensures that clock differences between the machines can be ignored. Two or three minutes should be more than 
enough; it would be fairly strange if a production machine's clock was more than 5 minutes difference from most 
atomic clocks around the world.

<a name="jws-read-clock-custom"></a>
##### Custom Clock Support

If the above `setAllowedClockSkewSeconds` isn't sufficient for your needs, the timestamps created
during parsing for timestamp comparisons can be obtained via a custom time source.  Call the `JwtParserBuilder`'s `setClock`
 method with an implementation of the `io.jsonwebtoken.Clock` interface.  For example:
 
 ```java
Clock clock = new MyClock();

Jwts.parserBuilder().setClock(myClock) //... etc ...
``` 

The `JwtParser`'s default `Clock` implementation simply returns `new Date()` to reflect the time when parsing occurs, 
as most would expect.  However, supplying your own clock could be useful, especially when writing test cases to 
guarantee deterministic behavior.

<a name="jws-read-decompression"></a>
#### JWS Decompression

If you used JJWT to compress a JWS and you used a custom compression algorithm, you will need to tell the `JwtParserBuilder`
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
you need to supply the codec to the `JwtParserBuilder` using the `setCompressionCodecResolver` method.  For example:

```java
CompressionCodecResolver ccr = new MyCompressionCodecResolver();

Jwts.parserBuilder()

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

If you don't explicitly configure a `JwtBuilder`'s `Serializer` or a `JwtParserBuilder`'s `Deserializer`, JJWT will 
automatically attempt to discover and use the following JSON implementations if found in the runtime classpath.  
They are checked in order, and the first one found is used:

1. Jackson: This will automatically be used if you specify `io.jsonwebtoken:jjwt-jackson` as a project runtime 
   dependency.  Jackson supports POJOs as claims with full marshaling/unmarshaling as necessary.
   
2. Gson: This will automatically be used if you specify `io.jsonwebtoken:jjwt-gson` as a project runtime dependency.
   Gson also supports POJOs as claims with full marshaling/unmarshaling as necessary. 
   
3. JSON-Java (`org.json`): This will be used automatically if you specify `io.jsonwebtoken:jjwt-orgjson` as a 
   project runtime dependency.
   
   **NOTE:** `org.json` APIs are natively enabled in Android environments so this is the recommended JSON processor for 
   Android applications _unless_ you want to use POJOs as claims.  The `org.json` library supports simple 
   Object-to-JSON marshaling, but it *does not* support JSON-to-Object unmarshalling.

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
    <version>0.11.2</version>
    <scope>compile</scope> <!-- Not runtime -->
</dependency>
```

**Gradle or Android**

```groovy
dependencies {
    compile 'io.jsonwebtoken:jjwt-jackson:0.11.2'
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

This would trigger the value in the `user` claim to be deserialized into the custom type of `User`.  Given the claims body of:

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

    .getBody()
    
    .get("user", User.class) // <-----
```

**NOTE:** Using this constructor is mutually exclusive with the `JacksonDeserializer(ObjectMapper)` constructor 
[described above](#json-jackson). This is because JJWT configures an `ObjectMapper` directly and could have negative 
consequences for a shared `ObjectMapper` instance. This should work for most applications, if you need a more advanced 
parsing options, [configure the mapper directly](#json-jackson).

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
new GsonBuilder().disableHtmlEscaping().create();
```

However, if you prefer to use a different Gson instance instead of JJWT's default, you can configure JJWT to use your 
own. 

You do this by declaring the `io.jsonwebtoken:jjwt-gson` dependency with **compile** scope (not runtime 
scope which is the typical JJWT default).  That is:

**Maven**

```xml
<dependency>
    <groupId>io.jsonwebtoken</groupId>
    <artifactId>jjwt-gson</artifactId>
    <version>0.11.2</version>
    <scope>compile</scope> <!-- Not runtime -->
</dependency>
```

**Gradle or Android**

```groovy
dependencies {
    compile 'io.jsonwebtoken:jjwt-gson:0.11.2'
}
```

And then you can specify the `GsonSerializer` using your own `Gson` instance on the `JwtBuilder`:

```java

Gson gson = getGson(); //implement me

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
string NOT is safe to expose publicly**.

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

Maintained by Les Hazlewood &amp; [Okta](https://okta.com/)

<a name="license"></a>
## License

This project is open-source via the [Apache 2.0 License](http://www.apache.org/licenses/LICENSE-2.0).
