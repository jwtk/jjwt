## Release Notes

### 0.9.1

This is a minor patch release that updates the Jackson dependency to 2.9.6 to address Jackson CVE-2017-17485.

### 0.9.0

This is a minor release that includes changes to dependencies and plugins to allow for building jjwt with Java 9.
Javadocs in a few classes were updated as well to support proper linting in both Java 8 and Java 9.

### 0.8.0

This is a minor feature enhancement, dependency version update and build update release. We switched from Jacoco to 
OpenClover as OpenClover delivers a higher quality of test metrics. As an interim measure, we introduced a new 
repository that has an updated version of the coveralls-maven-plugin which includes support for Clover reporting to
Coveralls. Once this change has been merged and released to the official coveralls-maven-plugin on maven central, 
this repository will be removed. The following dependencies were updated to the latest release version: maven 
compiler, maven enforcer, maven failsafe, maven release, maven scm provider, maven bundle, maven gpg, maven source, 
maven javadoc, jackson, bouncy castle, groovy, logback and powermock. Of significance, is the upgrade for jackson as 
a security issue was addressed in its latest release.

An `addClaims` method is added to the `JwtBuilder` interface in this release. It adds all given name/value pairs to
the JSON Claims in the payload.

Additional tests were added to improve overall test coverage.

### 0.7.0

This is a minor feature enhancement and bugfix release.  One of the bug fixes is particularly important if using
elliptic curve signatures, please see below.

#### Elliptic Curve Signature Length Bug Fix

Previous versions of JJWT safely calculated and verified Elliptic Curve signatures (no security risks), however, the
 signatures were encoded using the JVM's default ASN.1/DER format.  The JWS specification however 
requires EC signatures to be in a R + S format.  JJWT >= 0.7.0 now correctly represents newly computed EC signatures in 
this spec-compliant format.

What does this mean for you?

Signatures created from previous JJWT versions can still be verified, so your existing tokens will still be parsed 
correctly. HOWEVER, new JWTs with EC signatures created by JJWT >= 0.7.0 are now spec compliant and therefore can only 
be verified by JJWT >= 0.7.0 (or any other spec compliant library).

**This means that if you generate JWTs using Elliptic Curve Signatures after upgrading to JJWT >= 0.7.0, you _must_ 
also upgrade any applications that parse these JWTs to upgrade to JJWT >= 0.7.0 as well.**

#### Clock Skew Support

When parsing a JWT, you might find that `exp` or `nbf` claims fail because the clock on the parsing machine is not 
perfectly in sync with the clock on the machine that created the JWT.  You can now account for these differences 
(usually no more than a few minutes) when parsing using the new `setAllowedClockSkewSeconds` method on the parser.
For example:

```java
long seconds = 3 * 60; //3 minutes
Jwts.parser().setAllowedClockSkewSeconds(seconds).setSigningKey(key).parseClaimsJws(jwt);
```

This ensures that clock differences between machines can be ignored.  Two or three minutes should be more than enough; it
would be very strange if a machine's clock was more than 5 minutes difference from most atomic clocks around the world.

#### Custom Clock Support

Timestamps created during parsing can now be obtained via a custom time source via an implementation of
 the new `io.jsonwebtoken.Clock` interface.  The default implementation simply returns `new Date()` to reflect the time
  when parsing occurs, as most would expect.  However, supplying your own clock could be useful, especially during test 
  cases to guarantee deterministic behavior.

#### Android RSA Private Key Support

Previous versions of JJWT required RSA private keys to implement `java.security.interfaces.RSAPrivateKey`, but Android 
6 RSA private keys do not implement this interface.  JJWT now asserts that RSA keys are instances of both 
`java.security.interfaces.RSAKey` and `java.security.PrivateKey` which should work fine on both Android and all other
'standard' JVMs as well.

#### Library version updates

The few dependencies JWWT has (e.g. Jackson) have been updated to their latest stable versions at the time of release.

#### Issue List

For all completed issues, please see the [0.7.0 Milestone List](https://github.com/jwtk/jjwt/milestone/7?closed=1)

### 0.6.0

#### Enforce JWT Claims when Parsing

You can now enforce that JWT claims have expected values when parsing a compact JWT string.

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

#### Body Compression

**This feature is NOT JWT specification compliant**, *but it can be very useful when you parse your own tokens*.

If your JWT body is large and you have size restrictions (for example, if embedding a JWT in a URL and the URL must be under a certain length for legacy browsers or mail user agents), you may now compress the JWT body using a `CompressionCodec`:

```java
Jwts.builder().claim("foo", "someReallyLongDataString...")
    .compressWith(CompressionCodecs.DEFLATE) // or CompressionCodecs.GZIP
    .signWith(SignatureAlgorithm.HS256, key)
    .compact();
```

This will set a new `calg` header with the name of the compression algorithm used so that parsers can see that value and decompress accordingly.

The default parser implementation will automatically decompress DEFLATE or GZIP compressed bodies, so you don't need to set anything on the parser - it looks like normal:

```java
Jwts.parser().setSigningKey(key).parseClaimsJws(compact);
```

##### Custom Compression Algorithms

If the DEFLATE or GZIP algorithms are not sufficient for your needs, you can specify your own Compression algorithms by implementing the `CompressionCodec` interface and setting it on the parser:

```java
Jwts.builder().claim("foo", "someReallyLongDataString...")
    .compressWith(new MyCompressionCodec())
    .signWith(SignatureAlgorithm.HS256, key)
    .compact();
```

You will then need to specify a `CompressionCodecResolver` on the parser, so you can inspect the `calg` header and return your custom codec when discovered:

```java
Jwts.parser().setSigningKey(key)
    .setCompressionCodecResolver(new MyCustomCompressionCodecResolver())
    .parseClaimsJws(compact);
```

*NOTE*: Because body compression is not JWT specification compliant, you should only enable compression if both your JWT builder and parser are JJWT versions >= 0.6.0, or if you're using another library that implements the exact same functionality.  This feature is best reserved for your own use cases - where you both create and later parse the tokens.  It will likely cause problems if you compressed a token and expected a 3rd party (who doesn't use JJWT) to parse the token.

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
