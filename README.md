[![Build Status](https://travis-ci.org/jwtk/jjwt.svg?branch=master)](https://travis-ci.org/jwtk/jjwt)
[![Coverage Status](https://coveralls.io/repos/github/jwtk/jjwt/badge.svg?branch=master)](https://coveralls.io/github/jwtk/jjwt?branch=master)

## Java JWT: JSON Web Token for Java and Android

JJWT aims to be the easiest to use and understand library for creating and verifying JSON Web Tokens (JWTs) on the JVM.

JJWT is a Java implementation based on the [JWT](https://tools.ietf.org/html/rfc7519), [JWS](https://tools.ietf.org/html/rfc7515), [JWE](https://tools.ietf.org/html/rfc7516), [JWK](https://tools.ietf.org/html/rfc7517) and [JWA](https://tools.ietf.org/html/rfc7518) RFC specifications.

The library was created by [Okta's](http://www.okta.com) Senior Architect, [Les Hazlewood](https://github.com/lhazlewood)
and is now maintained by a [community](https://github.com/jwtk/jjwt/graphs/contributors) of contributors.

[Okta](https://developer.okta.com/) is a complete authentication and user management API for developers.

We've also added some convenience extensions that are not part of the specification, such as JWT compression and claim enforcement.

## What's a JSON Web Token?

Don't know what a JSON Web Token is? Read on. Otherwise, jump on down to the [Installation](#installation) section.

JWT is a means of transmitting information between two parties in a compact, verifiable form.

The bits of information encoded in the body of a JWT are called `claims`. The expanded form of the JWT is in a JSON format, so each `claim` is a key in the JSON object.
 
JWTs can be cryptographically signed (making it a [JWS](https://tools.ietf.org/html/rfc7515)) or encrypted (making it a [JWE](https://tools.ietf.org/html/rfc7516)).

This adds a powerful layer of verifiability to the user of JWTs. The receiver has a high degree of confidence that the JWT has not been tampered with by verifying the signature, for instance.

The compacted representation of a signed JWT is a string that has three parts, each separated by a `.`:

```
eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJKb2UifQ.ipevRNuRP6HflG8cFKnmUPtypruRC4fb1DWtoLL62SY
```

Each section is [base 64](https://en.wikipedia.org/wiki/Base64) encoded. The first section is the header, which at a minimum needs to specify the algorithm used to sign the JWT. The second section is the body. This section has all the claims of this JWT encoded in it. The final section is the signature. It's computed by passing a combination of the header and body through the algorithm specified in the header.
 
If you pass the first two sections through a base 64 decoder, you'll get the following (formatting added for clarity):

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

In this case, the information we have is that the HMAC using SHA-256 algorithm was used to sign the JWT. And, the body has a single claim, `sub` with value `Joe`.

There are a number of standard claims, called [Registered Claims](https://tools.ietf.org/html/rfc7519#section-4.1), in the specification and `sub` (for subject) is one of them.

To compute the signature, you must know the secret that was used to sign it. In this case, it was the word `secret`. You can see the signature creation is action [here](https://jsfiddle.net/dogeared/2fy2y0yd/11/) (Note: Trailing `=` are lopped off the signature for the JWT).

Now you know (just about) all you need to know about JWTs.

## Installation

Use your favorite Maven-compatible build tool to pull the dependency (and its transitive dependencies) from Maven Central:

Maven:

```xml
<dependency>
    <groupId>io.jsonwebtoken</groupId>
    <artifactId>jjwt</artifactId>
    <version>0.9.1</version>
</dependency>
```

Gradle:

```groovy
dependencies {
    compile 'io.jsonwebtoken:jjwt:0.9.1'
}
```

Note: JJWT depends on Jackson 2.x.  If you're already using an older version of Jackson in your app, [read this](#olderJackson)

## Quickstart

Most complexity is hidden behind a convenient and readable builder-based [fluent interface](http://en.wikipedia.org/wiki/Fluent_interface), great for relying on IDE auto-completion to write code quickly.  Here's an example:

```java
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.impl.crypto.MacProvider;
import java.security.Key;

// We need a signing key, so we'll create one just for this example. Usually
// the key would be read from your application configuration instead.
Key key = MacProvider.generateKey();

String compactJws = Jwts.builder()
  .setSubject("Joe")
  .signWith(SignatureAlgorithm.HS512, key)
  .compact();
```

How easy was that!?

In this case, we are *building* a JWT that will have the [registered claim](https://tools.ietf.org/html/rfc7519#section-4.1) `sub` (subject) set to `Joe`. We are signing the JWT using the HMAC using SHA-512 algorithm. finally, we are compacting it into its `String` form.

The resultant `String` looks like this:

```
eyJhbGciOiJIUzUxMiJ9.eyJzdWIiOiJKb2UifQ.yiV1GWDrQyCeoOswYTf_xvlgsnaVVYJM0mU6rkmRBf2T1MBl3Xh2kZii0Q9BdX5-G0j25Qv2WF4lA6jPl5GKuA
```

Now let's verify the JWT (you should always discard JWTs that don't match an expected signature):

```java
assert Jwts.parser().setSigningKey(key).parseClaimsJws(compactJws).getBody().getSubject().equals("Joe");
```

There are two things going on here. The `key` from before is being used to validate the signature of the JWT. If it fails to verify the JWT, a `SignatureException` is thrown. Assuming the JWT is validated, we parse out the claims and assert that that subject is set to `Joe`.

You have to love code one-liners that pack a punch!

But what if signature validation failed?  You can catch `SignatureException` and react accordingly:

```java
try {

    Jwts.parser().setSigningKey(key).parseClaimsJws(compactJws);

    //OK, we can trust this JWT

} catch (SignatureException e) {

    //don't trust the JWT!
}
```

## Supported Features

### Specification Compliant:

* Creating and parsing plaintext compact JWTs

* Creating, parsing and verifying digitally signed compact JWTs (aka JWSs) with all standard JWS algorithms:
    * HS256: HMAC using SHA-256
    * HS384: HMAC using SHA-384
    * HS512: HMAC using SHA-512
    * RS256: RSASSA-PKCS-v1_5 using SHA-256
    * RS384: RSASSA-PKCS-v1_5 using SHA-384
    * RS512: RSASSA-PKCS-v1_5 using SHA-512
    * PS256: RSASSA-PSS using SHA-256 and MGF1 with SHA-256
    * PS384: RSASSA-PSS using SHA-384 and MGF1 with SHA-384
    * PS512: RSASSA-PSS using SHA-512 and MGF1 with SHA-512
    * ES256: ECDSA using P-256 and SHA-256
    * ES384: ECDSA using P-384 and SHA-384
    * ES512: ECDSA using P-521 and SHA-512

### Enhancements Beyond the Specification:

* **Body compression.** If the JWT body is large, you can use a `CompressionCodec` to compress it. Best of all, the JJWT library will automtically decompress and parse the JWT without additional coding.

    ```java
    String compactJws =  Jwts.builder()
        .setSubject("Joe")
        .compressWith(CompressionCodecs.DEFLATE)
        .signWith(SignatureAlgorithm.HS512, key)
        .compact();
    ```

    If you examine the header section of the `compactJws`, it decodes to this:
    
    ```
    {
      "alg": "HS512",
      "zip": "DEF"
    }
    ```
    
    JJWT automatically detects that compression was used by examining the header and will automatically decompress when parsing. No extra coding is needed on your part for decompression.

* **Require Claims.** When parsing, you can specify that certain claims *must* be present and set to a certain value.

    ```java
    try {
        Jws<Claims> claims = Jwts.parser()
            .requireSubject("Joe")
            .require("hasMotorcycle", true)
            .setSigningKey(key)
            .parseClaimsJws(compactJws);
    } catch (MissingClaimException e) {
    
        // we get here if the required claim is not present
    
    } catch (IncorrectClaimException e) {
    
        // we get here if the required claim has the wrong value
    
    }
    ```

## Currently Unsupported Features

* [Non-compact](https://tools.ietf.org/html/draft-ietf-jose-json-web-signature-31#section-7.2) serialization and parsing.
* JWE (Encryption for JWT)

These feature sets will be implemented in a future release.  Community contributions are welcome!

## Learn More

- [JSON Web Token for Java and Android](https://stormpath.com/blog/jjwt-how-it-works-why/)
- [How to Create and Verify JWTs in Java](https://stormpath.com/blog/jwt-java-create-verify/)
- [Where to Store Your JWTs - Cookies vs HTML5 Web Storage](https://stormpath.com/blog/where-to-store-your-jwts-cookies-vs-html5-web-storage/)
- [Use JWT the Right Way!](https://stormpath.com/blog/jwt-the-right-way/)
- [Token Authentication for Java Applications](https://stormpath.com/blog/token-auth-for-java/)
- [JJWT Changelog](CHANGELOG.md)

<a name="olderJackson"></a>
#### Already using an older Jackson dependency?

JJWT depends on Jackson 2.8.x (or later).  If you are already using a Jackson version in your own application less than 2.x, for example 1.9.x, you will likely see [runtime errors](https://github.com/jwtk/jjwt/issues/1).  To avoid this, you should change your project build configuration to explicitly point to a 2.x version of Jackson.  For example:

```xml
<dependency>
    <groupId>com.fasterxml.jackson.core</groupId>
    <artifactId>jackson-databind</artifactId>
    <version>2.8.9</version>
</dependency>
```

## Author

Maintained by [Okta](https://okta.com/)

## Licensing

This project is open-source via the [Apache 2.0 License](http://www.apache.org/licenses/LICENSE-2.0).
