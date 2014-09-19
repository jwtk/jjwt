[![Build Status](https://travis-ci.org/jwtk/jjwt.svg?branch=master)](https://travis-ci.org/jwtk/jjwt)

# JSON Web Token for Java

This library is intended to be the easiest to use and understand library for creating JSON Web Tokens (JWTs) on the JVM, period.  Most complexity is hidden behind convenient and readable Builder chaining calls.  Here's an example:

    //Let's create a random signing key for testing:
    Random random = new SecureRandom();
    byte[] key = new byte[64];
    random.nextBytes(key);

    Claims claims = JWTs.claims().setIssuer("Me").setSubject("Joe")
                                 .setExpiration(new Date(System.currentTimeMillis() + 3600));

    String jwt = JWTs.builder().setClaims(claims).signWith(SigningAlgorithm.HS256, key).compact();

How easy was that!?

Now let's verify the JWT (you should always discard JWTs that don't match an expected signature):

    Token token = JWTs.parser().setSigningKey(key).parse(jwt);

    assert token.getClaims().getSubject().equals("Joe");

You have to love one-line code snippets in Java!

But what if signature validation failed?  You can catch `SignatureException` and react accordingly:

    try {

        JWTs.parser().setSigningKey(key).parse(jwt);

        //OK, we can trust this JWT

    } catch (SignatureException e) {

        //don't trust the JWT!
    }

## Supported Features

* Creating and parsing plaintext JWTs

* Creating and parsing digitally signed JWTs (aka JWSs) with the following algorithms:
    * HS256: HMAC using SHA-384
    * HS384: HMAC using SHA-384
    * HS512: HMAC using SHA-512
    * RS256: RSASSA-PKCS-v1_5 using SHA-256
    * RS384: RSASSA-PKCS-v1_5 using SHA-384
    * RS512: RSASSA-PKCS-v1_5 using SHA-512
    * PS256: RSASSA-PSS using SHA-256 and MGF1 with SHA-256
    * PS384: RSASSA-PSS using SHA-384 and MGF1 with SHA-384
    * PS512: RSASSA-PSS using SHA-512 and MGF1 with SHA-512

## Currently Unsupported Features

* Elliptic Curve signature algorithms ES256, ES384 and ES512 are not yet implemented.
* JWE (Encryption for JWT) is not yet implemented.

Both of these feature sets will be implemented in a future release when possible.  Community contributions are welcome!
