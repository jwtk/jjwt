[![Build Status](https://travis-ci.org/jwtk/jjwt.svg?branch=master)](https://travis-ci.org/jwtk/jjwt)

# Java JWT: JSON Web Token for Java and Android

JJWT aims to be the easiest to use and understand library for creating and verifying JSON Web Tokens (JWTs) on the JVM.

JJWT is a 'clean room' implementation based solely on the [JWT](https://tools.ietf.org/html/draft-ietf-oauth-json-web-token-25), [JWS](https://tools.ietf.org/html/draft-ietf-jose-json-web-signature-31), [JWE](https://tools.ietf.org/html/draft-ietf-jose-json-web-encryption-31) and [JWA](https://tools.ietf.org/html/draft-ietf-jose-json-web-algorithms-31) RFC draft specifications.

## Installation

Use your favorite Maven-compatible build tool to pull the dependency (and its transitive dependencies) from Maven Central:

Maven:

```xml
<dependency>
    <groupId>io.jsonwebtoken</groupId>
    <artifactId>jjwt</artifactId>
    <version>0.6</version>
</dependency>
```

Gradle:

```groovy
dependencies {
    compile 'io.jsonwebtoken:jjwt:0.6'
}
```

Note: JJWT depends on Jackson 2.x.  If you're already using an older version of Jackson in your app, [read this](#olderJackson)

## Usage

Most complexity is hidden behind a convenient and readable builder-based [fluent interface](http://en.wikipedia.org/wiki/Fluent_interface), great for relying on IDE auto-completion to write code quickly.  Here's an example:

```java
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.impl.crypto.MacProvider;
import java.security.Key;

// We need a signing key, so we'll create one just for this example. Usually
// the key would be read from your application configuration instead.
Key key = MacProvider.generateKey();

String s = Jwts.builder().setSubject("Joe").signWith(SignatureAlgorithm.HS512, key).compact();
```

How easy was that!?

Now let's verify the JWT (you should always discard JWTs that don't match an expected signature):

```java
assert Jwts.parser().setSigningKey(key).parseClaimsJws(s).getBody().getSubject().equals("Joe");
```

You have to love one-line code snippets!

But what if signature validation failed?  You can catch `SignatureException` and react accordingly:

```java
try {

    Jwts.parser().setSigningKey(key).parseClaimsJws(compactJwt);

    //OK, we can trust this JWT

} catch (SignatureException e) {

    //don't trust the JWT!
}
```

## Supported Features

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
    * ES512: ECDSA using P-512 and SHA-512

## Currently Unsupported Features

* [Non-compact](https://tools.ietf.org/html/draft-ietf-jose-json-web-signature-31#section-7.2) serialization and parsing.
* JWE (Encryption for JWT)

These feature sets will be implemented in a future release when possible.  Community contributions are welcome!

## Release Notes

### 0.6

#### Enforce JWT Values when Parsing

We added the ability to set expectations when parsing a JWT which ensures particular claims having particular values.

For example, let's say that you require that the JWT you are parsing has a specific `sub` (subject) value,
otherwise you may not trust the token.  You can do that by using one of the `require` methods on the parser builder:

```java
try {
    Jwts.parser().requireSubject("jsmith").setSigningKey(key).parseClaimsJws(s);
} catch(InvalidClaimException ice) {
    // the sub field was missing or did not have a 'jsmith' value
}
```

If it is important to react to a missing vs an incorrect value, instead of catching `InvalidClaimException`, you can catch either `MissingClaimException` or `IncorrectClaimException`:

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
(or, again, you could catch either MissingClaimException or IncorrectClaimException instead)

### 0.5.1

- Minor [bug](https://github.com/jwtk/jjwt/issues/31) fix [release](https://github.com/jwtk/jjwt/issues?q=milestone%3A0.5.1+is%3Aclosed) that ensures correct Base64 padding in Android runtimes.

### 0.5

- Android support! Android's built-in Base64 codec will be used if JJWT detects it is running in an Android environment.  Other than Base64, all other parts of JJWT were already Android-compliant.  Now it is fully compliant.

- Elliptic Curve signature algorithms!  `SignatureAlgorithm.ES256`, `ES384` and `ES512` are now supported.

- Super convenient key generation methods, so you don't have to worry how to do this safely:
  - `MacProvider.generateKey(); //or generateKey(SignatureAlgorithm)`
  - `RsaProvider.generateKeyPair(); //or generateKeyPair(sizeInBits)`
  - `EllipticCurveProvider.generateKeyPair(); //or generateKeyPair(SignatureAlgorithm)`

  The `generate`* methods that accept an `SignatureAlgorithm` argument know to generate a key of sufficient strength that reflects the specified algorithm strength.

Please see the full [0.5 closed issues list](https://github.com/jwtk/jjwt/issues?q=milestone%3A0.5+is%3Aclosed) for more information.

### 0.4

- [Issue 8](https://github.com/jwtk/jjwt/issues/8): Add ability to find signing key by inspecting the JWS values before verifying the signature.

This is a handy little feature.  If you need to parse a signed JWT (a JWS) and you don't know which signing key was used to sign it, you can now use the new `SigningKeyResolver` concept.

A `SigningKeyresolver` can inspect the JWS header and body (Claims or String) _before_ the JWS signature is verified. By inspecting the data, you can find the key and return it, and the parser will use the returned key to validate the signature.  For example:

```java
SigningKeyResolver resolver = new MySigningKeyResolver();

Jws<Claims> jws = Jwts.parser().setSigningKeyResolver(resolver).parseClaimsJws(compact);
```

The signature is still validated, and the JWT instance will still not be returned if the jwt string is invalid, as expected.  You just get to 'see' the JWT data for key discovery before the parser validates.  Nice.

This of course requires that you put some sort of information in the JWS when you create it so that your `SigningKeyResolver` implementation can look at it later and look up the key.  The *standard* way to do this is to use the JWS `kid` ('key id') field, for example:

```java
Jwts.builder().setHeaderParam("kid", your_signing_key_id_NOT_THE_SECRET).build();
```

You could of course set any other header parameter or claims parameter instead of setting `kid` if you want - that's just the default field reserved for signing key identification.  If you can locate the signing key based on other information in the header or claims, you don't need to set the `kid` field - just make sure your resolver implementation knows how to look up the key.

Finally, a nice `SigningKeyResolverAdapter` is provided to allow you to write quick and simple subclasses or anonymous classes instead of having to implement the `SigningKeyResolver` interface directly.  For example:

```java
Jws<Claims> jws = Jwts.parser().setSigningKeyResolver(new SigningKeyResolverAdapter() {
        @Override
        public byte[] resolveSigningKeyBytes(JwsHeader header, Claims claims) {
            //inspect the header or claims, lookup and return the signing key
            String keyId = header.getKeyId(); //or any other field that you need to inspect
            return getSigningKey(keyId); //implement me
        }})
    .parseClaimsJws(compact);
```

### 0.3

- [Issue 6](https://github.com/jwtk/jjwt/issues/6): Parsing an expired Claims JWT or JWS (as determined by the `exp` claims field) will now throw an `ExpiredJwtException`.
- [Issue 7](https://github.com/jwtk/jjwt/issues/7): Parsing a premature Claims JWT or JWS (as determined by the `nbf` claims field) will now throw a `PrematureJwtException`.

### 0.2

#### More convenient Claims building

This release adds convenience methods to the `JwtBuilder` interface so you can set claims directly on the builder without having to create a separate Claims instance/builder, reducing the amount of code you have to write.  For example, this:

```java
Claims claims = Jwts.claims().setSubject("Joe");

String compactJwt = Jwts.builder().setClaims(claims).signWith(HS256, key).compact();
```

can now be written as:

```java
String compactJwt = Jwts.builder().setSubject("Joe").signWith(HS256, key).compact();
```

A Claims instance based on the specified claims will be created and set as the JWT's payload automatically.

#### Type-safe handling for JWT and JWS with generics

The following < 0.2 code produced a JWT as expected:

```java
Jwt jwt = Jwts.parser().setSigningKey(key).parse(compact);
```

But you couldn't easily determine if the `jwt` was a `JWT` or `JWS` instance or if the body was a `Claims` instance or a plaintext `String` without resorting to a bunch of yucky `instanceof` checks.  In 0.2, we introduce the `JwtHandler` when you don't know the exact format of the compact JWT string ahead of time, and parsing convenience methods when you do.

##### JwtHandler

If you do not know the format of the compact JWT string at the time you try to parse it, you can determine what type it is after parsing by providing a `JwtHandler` instance to the `JwtParser` with the new `parse(String compactJwt, JwtHandler handler)` method.  For example:

```java
T returnVal = Jwts.parser().setSigningKey(key).parse(compact, new JwtHandler<T>() {
    @Override
    public T onPlaintextJwt(Jwt<Header, String> jwt) {
        //the JWT parsed was an unsigned plaintext JWT
        //inspect it, then return an instance of T (see returnVal above)
    }

    @Override
    public T onClaimsJwt(Jwt<Header, Claims> jwt) {
        //the JWT parsed was an unsigned Claims JWT
        //inspect it, then return an instance of T (see returnVal above)
    }

    @Override
    public T onPlaintextJws(Jws<String> jws) {
        //the JWT parsed was a signed plaintext JWS
        //inspect it, then return an instance of T (see returnVal above)
    }

    @Override
    public T onClaimsJws(Jws<Claims> jws) {
        //the JWT parsed was a signed Claims JWS
        //inspect it, then return an instance of T (see returnVal above)
    }
});
```

Of course, if you know you'll only have to parse a subset of the above, you can use the `JwtHandlerAdapter` and implement only the methods you need.  For example:

```java
T returnVal = Jwts.parser().setSigningKey(key).parse(plaintextJwt, new JwtHandlerAdapter<Jwt<Header, T>>() {
    @Override
    public T onPlaintextJws(Jws<String> jws) {
        //the JWT parsed was a signed plaintext JWS
        //inspect it, then return an instance of T (see returnVal above)
    }

    @Override
    public T onClaimsJws(Jws<Claims> jws) {
        //the JWT parsed was a signed Claims JWS
        //inspect it, then return an instance of T (see returnVal above)
    }
});
```

##### Known Type convenience parse methods

If, unlike above, you are confident of the compact string format and know which type of JWT or JWS it will produce, you can just use one of the 4 new convenience parsing methods to get exactly the type of JWT or JWS you know exists.  For example:

```java

//for a known plaintext jwt string:
Jwt<Header,String> jwt = Jwts.parser().parsePlaintextJwt(compact);

//for a known Claims JWT string:
Jwt<Header,Claims> jwt = Jwts.parser().parseClaimsJwt(compact);

//for a known signed plaintext JWT (aka a plaintext JWS):
Jws<String> jws = Jwts.parser().setSigningKey(key).parsePlaintextJws(compact);

//for a known signed Claims JWT (aka a Claims JWS):
Jws<Claims> jws = Jwts.parser().setSigningKey(key).parseClaimsJws(compact);

```

<a name="olderJackson"></a>
#### Already using an older Jackson dependency?

JJWT depends on Jackson 2.4.x (or later).  If you are already using a Jackson version in your own application less than 2.x, for example 1.9.x, you will likely see [runtime errors](https://github.com/jwtk/jjwt/issues/1).  To avoid this, you should change your project build configuration to explicitly point to a 2.x version of Jackson.  For example:

```xml
<dependency>
    <groupId>com.fasterxml.jackson.core</groupId>
    <artifactId>jackson-databind</artifactId>
    <version>2.4.2</version>
</dependency>
```
