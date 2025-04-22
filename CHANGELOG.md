## Release Notes

### 0.12.7

This patch release:

* Improves performance slightly by ensuring all `jjwt-api` utility methods that create `*Builder` instances (`Jwts.builder()`, `Jwts.parserBuilder()`, `Jwks.builder()`, etc) no longer use reflection.
 
  Instead,`static` factories are created via reflection only once during initial `jjwt-api` classloading, and then `*Builder`s are created via standard instantiation using the `new` operator thereafter.  This also benefits certain environments that may not have ideal `ClassLoader` implementations (e.g. Tomcat in some cases).
 
  **NOTE: because this changes which classes are loaded via reflection, any environments that must explicitly reference reflective class names (e.g. GraalVM applications) will need to be updated to reflect the new factory class names**.
  
  See [Issue 988](https://github.com/jwtk/jjwt/issues/988).

### 0.12.6

This patch release:

* Ensures that after successful JWS signature verification, an application-configured Base64Url `Decoder` output is
  used to construct a `Jws` instance (instead of JJWT's default decoder). See
  [Issue 947](https://github.com/jwtk/jjwt/issues/947).
* Fixes a decompression memory leak in concurrent/multi-threaded environments introduced in 0.12.0 when decompressing JWTs with a `zip` header of `GZIP`. See [Issue 949](https://github.com/jwtk/jjwt/issues/949).
* Upgrades BouncyCastle to 1.78 via [PR 941](https://github.com/jwtk/jjwt/pull/941).
* Ensures that a `JwkSet`'s `keys` list member is no longer considered secret and is not redacted by default. However, each individual JWK element within the `keys` list may still have [redacted private or secret members](https://github.com/jwtk/jjwt?tab=readme-ov-file#jwk-tostring-safety) as expected. See [Issue 976](https://github.com/jwtk/jjwt/issues/976).

### 0.12.5

This patch release:

* Ensures that builders' `NestedCollection` changes are applied to the collection immediately as mutation methods are called, no longer
  requiring application developers to call `.and()` to 'commit' or apply a change.  For example, prior to this release,
  the following code did not apply changes:
  ```java
  JwtBuilder builder = Jwts.builder();
  builder.audience().add("an-audience"); // no .and() call
  builder.compact(); // would not keep 'an-audience'
  ```
  Now this code works as expected and all other `NestedCollection` instances like it apply changes immediately (e.g. when calling
  `.add(value)`).
  
  However, standard fluent builder chains are still recommended for readability when feasible, e.g.
  
  ```java
  Jwts.builder()
      .audience().add("an-audience").and() // allows fluent chaining
      .subject("Joe")
      // etc...
      .compact()
  ```
  See [Issue 916](https://github.com/jwtk/jjwt/issues/916).

### 0.12.4

This patch release includes various changes listed below.

#### Jackson Default Parsing Behavior

This release makes two behavioral changes to JJWT's default Jackson `ObjectMapper` parsing settings:

1. In the interest of having stronger standards to reject potentially malformed/malicious/accidental JSON that could
   have undesirable effects on an application, JJWT's default `ObjectMapper `is now configured to explicitly reject/fail 
   parsing JSON (JWT headers and/or Claims) if/when that JSON contains duplicate JSON member names. 
   
   For example, now the following JSON, if parsed, would fail (be rejected) by default:
   ```json
   {
     "hello": "world",
     "thisWillFail": 42,
     "thisWillFail": "test"
   }
    ```
   
   Technically, the JWT RFCs _do allow_ duplicate named fields as long as the last parsed member is the one used
   (see [JWS RFC 7515, Section 4](https://datatracker.ietf.org/doc/html/rfc7515#section-4)), so this is allowed.
   However, because JWTs often reflect security concepts, it's usually better to be defensive and reject these 
   unexpected scenarios by default. The RFC later supports this position/preference in 
   [Section 10.12](https://datatracker.ietf.org/doc/html/rfc7515#section-10.12):
       
       Ambiguous and potentially exploitable situations
       could arise if the JSON parser used does not enforce the uniqueness
       of member names or returns an unpredictable value for duplicate
       member names.
       
   Finally, this is just a default, and the RFC does indeed allow duplicate member names if the last value is used,
   so applications that require duplicates to be allowed can simply configure their own `ObjectMapper` and use
   that with JJWT instead of assuming this (new) JJWT default. See 
   [Issue #877](https://github.com/jwtk/jjwt/issues/877) for more.
2. If using JJWT's support to use Jackson to parse 
   [Custom Claim Types](https://github.com/jwtk/jjwt#json-jackson-custom-types) (for example, a Claim that should be
   unmarshalled into a POJO), and the JSON for that POJO contained a member that is not represented in the specified
   class, Jackson would fail parsing by default.  Because POJOs and JSON data models can sometimes be out of sync
   due to different class versions, the default behavior has been changed to ignore these unknown JSON members instead 
   of failing (i.e. the `ObjectMapper`'s  `DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES` is now set to `false`)
   by default.
   
   Again, if you prefer the stricter behavior of rejecting JSON with extra or unknown properties, you can configure
   `true` on your own `ObjectMapper` instance and use that instance with the `Jwts.parser()` builder.

#### Additional Changes

This release also:

* Fixes a thread-safety issue when using `java.util.ServiceLoader` to dynamically lookup/instantiate pluggable 
  implementations of JJWT interfaces (e.g. JSON parsers, etc).  See 
  [Issue #873](https://github.com/jwtk/jjwt/issues/873) and its documented fix in 
  [PR #893](https://github.com/jwtk/jjwt/pull/892).
* Ensures Android environments and older `org.json` library usages can parse JSON from a `JwtBuilder`-provided
  `java.io.Reader` instance. [Issue 882](https://github.com/jwtk/jjwt/issues/882).
* Ensures a single string `aud` (Audience) claim is retained (without converting it to a `Set`) when copying/applying a 
  source Claims instance to a destination Claims builder. [Issue 890](https://github.com/jwtk/jjwt/issues/890).
* Ensures P-256, P-384 and P-521 Elliptic Curve JWKs zero-pad their field element (`x`, `y`, and `d`) byte array values
  if necessary before Base64Url-encoding per [RFC 7518](https://datatracker.ietf.org/doc/html/rfc7518), Sections 
  [6.2.1.2](https://datatracker.ietf.org/doc/html/rfc7518#section-6.2.1.2), 
  [6.2.1.3](https://datatracker.ietf.org/doc/html/rfc7518#section-6.2.1.3), and
  [6.2.2.1](https://datatracker.ietf.org/doc/html/rfc7518#section-6.2.2.1), respectively. 
  [Issue 901](https://github.com/jwtk/jjwt/issues/901).
* Ensures that Secret JWKs for HMAC-SHA algorithms with `k` sizes larger than the algorithm minimum can
  be parsed/used as expected. See [Issue #905](https://github.com/jwtk/jjwt/issues/905) 
* Ensures there is an upper bound (maximum) iterations enforced for PBES2 decryption to help mitigate potential DoS 
  attacks. Many thanks to Jingcheng Yang and Jianjun Chen from Sichuan University and Zhongguancun Lab for their 
  work on this. See [PR 911](https://github.com/jwtk/jjwt/pull/911).
* Fixes various typos in documentation and JavaDoc. Thanks to those contributing pull requests for these!

### 0.12.3

This patch release:

* Upgrades the `org.json` dependency to `20231013` to address that library's
  [CVE-2023-5072](https://nvd.nist.gov/vuln/detail/CVE-2023-5072) vulnerability.
* (Re-)enables empty values for custom claims, which was the behavior in <= 0.11.5. 
  [Issue 858](https://github.com/jwtk/jjwt/issues/858).

### 0.12.2

This is a follow-up release to finalize the work in 0.12.1 that tried to fix a reflection scope problem
on >= JDK 17.  The 0.12.1 fix worked, but only if the importing project or application did _not_ have its own
`module-info.java` file.

This release removes that reflection code entirely in favor of a JJWT-native implementation, eliminating JPMS 
module (scope) problems on >= JDK 17. As such, `--add-opens` flags are no longer required to use JJWT.

The fix has been tested up through JDK 21 in a separate application environment (out of JJWT's codebase) to assert
expected functionality in a 'clean room' environment in a project both with and without `module-info.java` usage.

### 0.12.1

Enabled reflective access on JDK 17+ to `java.io.ByteArrayInputStream` and `sun.security.util.KeyUtil` for
`jjwt-impl.jar`

### 0.12.0

This is a big release! JJWT now fully supports Encrypted JSON Web Tokens (JWE), JSON Web Keys (JWK) and more!  See the 
sections below enumerating all new features as well as important notes on breaking changes or backwards-incompatible 
changes made in preparation for the upcoming 1.0 release.

**Because breaking changes are being introduced, it is strongly recommended to wait until the upcoming 1.0 release
where you can address breaking changes one time only**.

Those that need immediate JWE encryption and JWK key support
however will likely want to upgrade now and deal with the smaller subset of breaking changes in the 1.0 release.

#### Simplified Starter Jar

Those upgrading to new modular JJWT versions from old single-jar versions will transparently obtain everything 
they need in their Maven, Gradle or Android projects.

JJWT's early releases had one and only one .jar: `jjwt.jar`.  Later releases moved to a modular design with 'api' and
'impl' jars including 'plugin' jars for Jackson, GSON, org.json, etc.  Some users upgrading from the earlier single 
jar to JJWT's later versions have been frustrated by being forced to learn how to configure the more modular .jars.

This release re-introduces the `jjwt.jar` artifact again, but this time it is simply an empty .jar with Maven 
metadata that will automatically transitively download the following into a project, retaining the old single-jar 
behavior:
* `jjwt-api.jar`
* `jjwt-impl.jar`
* `jjwt-jackson.jar`

Naturally, developers are still encouraged to configure the modular .jars as described in JJWT's documentation for 
greater control and to enable their preferred JSON parser, but this stop-gap should help those unaware when upgrading.

#### JSON Web Encryption (JWE) Support!

This has been a long-awaited feature for JJWT, years in the making, and it is quite extensive - so many encryption 
algorithms and key management algorithms are defined by the JWA specification, and new API concepts had to be 
introduced for all of them, as well as extensive testing with RFC-defined test vectors.  The wait is over!  
All JWA-defined encryption algorithms and key management algorithms are fully implemented and supported and 
available immediately.  For example:

```java
AeadAlgorithm enc = Jwts.ENC.A256GCM;
SecretKey key = enc.key().build();
String compact = Jwts.builder().setSubject("Joe").encryptWith(key, enc).compact();

Jwe<Claims> jwe = Jwts.parser().decryptWith(key).build().parseEncryptedClaims(compact);
```

Many other RSA and Elliptic Curve examples are in the full README documentation. 

#### JSON Web Key (JWK) Support!

Representing cryptographic keys - SecretKeys, RSA Public and Private Keys, Elliptic Curve Public and 
Private keys - as fully encoded JSON objects according to the JWK specification - is now fully implemented and
supported.  The new `Jwks` utility class exists to create JWK builders and parsers as desired.  For example:

```java
SecretKey key = Jwts.SIG.HS256.key().build();
SecretJwk jwk = Jwks.builder().forKey(key).build();
assert key.equals(jwk.toKey());

// or if receiving a JWK string:
Jwk<?> parsedJwk = Jwks.parser().build().parse(jwkString);
assert jwk.equals(parsedJwk);
assert key.equals(parsedJwk.toKey());
```

Many JJWT users won't need to use JWKs explicitly, but some JWA Key Management Algorithms (and lots of RFC test 
vectors) utilize JWKs when transmitting JWEs.  As this was required by JWE, it is now implemented in full for 
JWE use as well as general-purpose JWK support.

#### JWK Thumbprint and JWK Thumbprint URI support

The [JWK Thumbprint](https://www.rfc-editor.org/rfc/rfc7638.html) and 
[JWK Thumbprint URI](https://www.rfc-editor.org/rfc/rfc9278.html) RFC specifications are now fully supported.  Please
see the README.md file's corresponding named sections for both for full documentation and usage examples.

#### JWS Unencoded Payload Option (`b64`) support

The [JSON Web Signature (JWS) Unencoded Payload Option](https://www.rfc-editor.org/rfc/rfc7797.html) RFC specification
is now fully supported.  Please see the README.md corresponding named section for documentation and usage examples.

#### Better PKCS11 and Hardware Security Module (HSM) support

Previous versions of JJWT enforced that Private Keys implemented the `RSAKey` and `ECKey` interfaces to enforce key 
length requirements.  With this release, JJWT will still perform those checks when those data types are available, 
but if not, as is common with keys from PKCS11 and HSM KeyStores, JJWT will still allow those Keys to be used, 
expecting the underlying Security Provider to enforce any key requirements. This should reduce or eliminate any 
custom code previously written to extend JJWT to use keys from those KeyStores or Providers.

Additionally, PKCS11/HSM tests using [SoftHSMv2](https://www.opendnssec.org/softhsm/) are run on every build with
every JWS MAC and Signature algorithm and every JWE Key algorithm to ensure continued stable support with
Android and Sun PKCS11 implementations and spec-compliant Hardware Security Modules that use the PKCS11 interface
(such as YubiKey, etc.)

#### Custom Signature Algorithms

The `io.jsonwebtoken.SignatureAlgorithm` enum has been deprecated in favor of new 
`io.jsonwebtoken.security.SecureDigestAlgorithm`, `io.jsonwebtoken.security.MacAlgorithm`, and 
`io.jsonwebtoken.security.SignatureAlgorithm` interfaces to allow custom algorithm implementations.  The new nested
`Jwts.SIG` static inner class is a registry of all standard JWS algorithms as expected, exactly like the 
old enum.  This change was made because enums are a static concept by design and cannot 
support custom values: those who wanted to use custom signature algorithms could not do so until now.  The new 
interfaces now allow anyone to plug in and support custom algorithms with JJWT as desired.

#### KeyBuilder and KeyPairBuilder

Because the `io.jsonwebtoken.security.Keys#secretKeyFor` and `io.jsonwebtoken.security.Keys#keyPairFor` methods 
accepted the now-deprecated `io.jsonwebtoken.SignatureAlgorithm` enum, they have also been deprecated in favor of 
calling new `key()` or `keyPair()` builder methods on `MacAlgorithm` and `SignatureAlgorithm` instances directly.  
For example:

```java
SecretKey key = Jwts.SIG.HS256.key().build();
KeyPair pair = Jwts.SIG.RS256.keyPair().build();
```

The builders allow for customization of the JCA `Provider` and `SecureRandom` during Key or KeyPair generation if desired, whereas
the old enum-based static utility methods did not.

#### Preparation for 1.0

Now that the JWE and JWK specifications are implemented, only a few things remain for JJWT to be considered at 
version 1.0.  We have been waiting to apply the 1.0 release version number until the entire set of JWT specifications 
are fully supported **and** we drop JDK 7 support (to allow users to use JDK 8 APIs).  To that end, we have had to 
deprecate some concepts, or in some cases, completely break backwards compatibility to ensure the transition to 
1.0 (and JDK 8 APIs) are possible.  Most backwards-incompatible changes are listed in the next section below.

#### Backwards Compatibility Breaking Changes, Warnings and Deprecations

* `io.jsonwebtoken.Jwt`'s `getBody()` method has been deprecated in favor of a new `getPayload()` method to
  reflect correct JWT specification nomenclature/taxonomy.


* `io.jsonwebtoken.Jws`'s `getSignature()` method has been deprecated in favor of a new `getDigest()` method to
  support expected congruent behavior with `Jwe` instances (both have digests).


* `io.jsonwebtoken.JwtParser`'s `parseContentJwt`, `parseClaimsJwt`, `parseContentJws`, and `parseClaimsJws` methods
  have been deprecated in favor of more intuitive respective `parseUnsecuredContent`, `parseUnsecuredClaims`,
  `parseSignedContent` and `parseSignedClaims` methods.


* `io.jsonwebtoken.CompressionCodec` is now deprecated in favor of the new `io.jsonwebtoken.io.CompressionAlgorithm`
  interface. This is to guarantee API congruence with all other JWT-identifiable algorithm IDs that can be set as a 
  header value.


* `io.jsonwebtoken.CompressionCodecResolver` has been deprecated in favor of the new
  `JwtParserBuilder#addCompressionAlgorithms` method.


#### Breaking Changes

* **`io.jsonwebtoken.Claims` and `io.jsonwebtoken.Header` instances are now immutable** to enhance security and thread
  safety.  Creation and mutation are supported with newly introduced `ClaimsBuilder` and `HeaderBuilder` concepts.
  Even though mutation methods have migrated, there are a couple that have been removed entirely:
  * `io.jsonwebtoken.JwsHeader#setAlgorithm` has been removed - the `JwtBuilder` will always set the appropriate
    `alg` header automatically based on builder state.
  * `io.jsonwebtoken.Header#setCompressionAlgorithm` has been removed - the `JwtBuilder` will always set the appropriate
  `zip` header automatically based on builder state.


* `io.jsonwebtoken.Jwts`'s `header(Map)`, `jwsHeader()` and `jwsHeader(Map)` methods have been removed in favor
  of the new `header()` method that returns a `HeaderBuilder` to support method chaining and dynamic `Header` type 
  creation. The `HeaderBuilder` will dynamically create a `Header`, `JwsHeader` or `JweHeader` automatically based on 
  builder state.


* Similarly, `io.jsonwebtoken.Jwts`'s `claims()` static method has been changed to return a `ClaimsBuilder` instead
  of a `Claims` instance.


* **JWTs that do not contain JSON Claims now have a payload type of `byte[]` instead of `String`** (that is, 
  `Jwt<byte[]>` instead of `Jwt<String>`).  This is because JWTs, especially when used with the 
  `cty` (Content Type) header, are capable of handling _any_ type of payload, not just Strings. The previous JJWT 
  releases didn't account for this, and now the API accurately reflects the JWT RFC specification payload 
  capabilities. Additionally, the name of `plaintext` has been changed to `content` in method names and JavaDoc to 
  reflect this taxonomy. This change has impacted the following JJWT APIs:

  * The `JwtBuilder`'s `setPayload(String)` method has been deprecated in favor of two new methods:
  
    * `setContent(byte[])`, and 
    * `setContent(byte[], String contentType)`
    
    These new methods allow any kind of content
    within a JWT, not just Strings. The existing `setPayload(String)` method implementation has been changed to 
    delegate to this new `setContent(byte[])` method with the argument's UTF-8 bytes, for example 
    `setContent(payloadString.getBytes(StandardCharsets.UTF_8))`.

  * The `JwtParser`'s `Jwt<Header, String> parsePlaintextJwt(String plaintextJwt)` and
    `Jws<String> parsePlaintextJws(String plaintextJws)` methods have been changed to
    `Jwt<Header, byte[]> parseContentJwt(String plaintextJwt)` and
    `Jws<byte[]> parseContentJws(String plaintextJws)` respectively.

  * `JwtHandler`'s `onPlaintextJwt(String)` and `onPlaintextJws(String)` methods have been changed to
    `onContentJwt(byte[])` and `onContentJws(byte[])` respectively.

  * `io.jsonwebtoken.JwtHandlerAdapter` has been changed to reflect the above-mentioned name and `String`-to-`byte[]` 
    argument changes, as well adding the `abstract` modifier.  This class was never intended
    to be instantiated directly, and is provided for subclassing only.  The missing modifier has been added to ensure
    the class is used as it had always been intended.

  * `io.jsonwebtoken.SigningKeyResolver`'s `resolveSigningKey(JwsHeader, String)` method has been changed to
    `resolveSigningKey(JwsHeader, byte[])`.


* `io.jsonwebtoken.JwtParser` is now immutable.  All mutation/modification methods (setters, etc) deprecated 4 years 
  ago have been removed.  All parser configuration requires using the `JwtParserBuilder`.


* Similarly, `io.jsonwebtoken.Jwts`'s `parser()` method deprecated 4 years ago has been changed to now return a 
  `JwtParserBuilder` instead of a direct `JwtParser` instance.  The previous `Jwts.parserBuilder()` method has been 
  removed as it is now redundant.


* The `JwtParserBuilder` no longer supports `PrivateKey`s for signature verification.  This was an old
  legacy behavior scheduled for removal years ago, and that change is now complete.  For various cryptographic/security
  reasons, asymmetric public/private key signatures should always be created with `PrivateKey`s and verified with
  `PublicKey`s.


* `io.jsonwebtoken.CompressionCodec` implementations are no longer discoverable via `java.util.ServiceLoader` due to
  runtime performance problems with the JDK's `ServiceLoader` implementation per
  https://github.com/jwtk/jjwt/issues/648.  Custom implementations should be made available to the `JwtParser` via
  the new `JwtParserBuilder#addCompressionAlgorithms` method.


* Prior to this release, if there was a serialization problem when serializing the JWT Header, an `IllegalStateException`
  was thrown. If there was a problem when serializing the JWT claims, an `IllegalArgumentException` was
  thrown.  This has been changed up to ensure consistency: any serialization error with either headers or claims
  will now throw a `io.jsonwebtoken.io.SerializationException`.


* Parsing of unsecured JWTs (`alg` header of `none`) are now disabled by default as mandated by 
  [RFC 7518, Section 3.6](https://www.rfc-editor.org/rfc/rfc7518.html#section-3.6). If you require parsing of
  unsecured JWTs, you must call the `JwtParserBuilder#enableUnsecured()` method, but note the security
  implications mentioned in that method's JavaDoc before doing so.


* `io.jsonwebtoken.gson.io.GsonSerializer` now requires `Gson` instances that have a registered
  `GsonSupplierSerializer` type adapter, for example:
  ```java
  new GsonBuilder()
    .registerTypeHierarchyAdapter(io.jsonwebtoken.lang.Supplier.class, GsonSupplierSerializer.INSTANCE)    
    .disableHtmlEscaping().create();
  ```
  This is to ensure JWKs have `toString()` and application log safety (do not print secure material), but still 
  serialize to JSON correctly.


* `io.jsonwebtoken.InvalidClaimException` and its two subclasses (`IncorrectClaimException` and `MissingClaimException`)
  were previously mutable, allowing the corresponding claim name and claim value to be set on the exception after
  creation.  These should have always been immutable without those setters (just getters), and this was a previous
  implementation oversight.  This release has ensured they are immutable without the setters.

### 0.11.5

This patch release adds additional security guards against an ECDSA bug in Java SE versions 15-15.0.6, 17-17.0.2, and 18
([CVE-2022-21449](https://nvd.nist.gov/vuln/detail/CVE-2022-21449)) in addition to the guards added in the JJWT 0.11.3 
release. This patch allows JJWT users using those JVM versions to upgrade to JJWT 0.11.5, even if they are unable to 
upgrade their JVM to patched/fixed JVM version in a timely manner.  Note: if your application does not use these JVM 
versions, you are not exposed to the JVM vulnerability.

Note that the CVE is not a bug within JJWT itself - it is a bug within the above listed JVM versions, and the
JJWT 0.11.5 release adds additional precautions within JJWT in case an application team is not able to upgrade
their JVM in a timely manner.

However, even with these additional JJWT security guards, the root cause of the issue is the JVM, so it **strongly
recommended** to upgrade your JVM to version
15.0.7, 17.0.3, or 18.0.1 or later to ensure the bug does not surface elsewhere in your application code or any other
third party library in your application that may not contain similar security guards. 

Issues included in this patch are listed in the [JJWT 0.11.5 milestone](https://github.com/jwtk/jjwt/milestone/26?closed=1).

#### Credits

Thank you to [Neil Madden](https://neilmadden.blog), the security researcher that first discovered the JVM
vulnerability as covered in his [Psychic Signatures in Java](https://neilmadden.blog/2022/04/19/psychic-signatures-in-java/) 
blog post.  Neil worked directly with the JJWT team to provide these additional guards, beyond what was in the JJWT 0.11.3
release, and we're grateful for his help and collaboration in reviewing our fixes and for the additional tests he
provided the JJWT team.

### 0.11.4

This patch release:

* Adds additional handling for rare JSON parsing exceptions and wraps them in a `JwtException` to allow the application to handle these conditions as JWT concerns.
* Upgrades the `jjwt-jackson` module's Jackson dependency to `2.12.6.1`.
* Upgrades the `jjwt-orgjson` module's org.json:json dependency to `20220320`.
* Upgrades the `jjwt-gson` module's gson dependency to `2.9.0`.
* Upgrades the internal testing BouncyCastle version and any references in README documentation examples to `1.70`.
* Contains various documentation and typo fixes.

The patch also makes various internal project POM and build enhancements to reduce repetition and the chance for 
stale references, and overall create a cleaner build with less warnings.  It also ensures that CI testing builds
and executes on all latest OpenJDK versions from Java 7 to Java 18 (inclusive).

Issues included in this patch are listed in the [JJWT 0.11.4 milestone](https://github.com/jwtk/jjwt/milestone/25?closed=1).

### 0.11.3

This patch release adds security guards against an ECDSA bug in Java SE versions 15-15.0.6, 17-17.0.2, and 18
([CVE-2022-21449](https://nvd.nist.gov/vuln/detail/CVE-2022-21449)). Note: if your application does not use these 
JVM versions, you are not exposed to the JVM vulnerability.

Note that the CVE is not a bug within JJWT itself - it is a bug within the above listed JVM versions.  However, even 
with these additional JJWT security guards, the root cause of the issue is the JVM, so it **strongly 
recommended** to upgrade your JVM to version 15.0.7, 17.0.3, or 18.0.1 or later to ensure the bug does not surface 
elsewhere in your application code or any other third party library in your application that may not contain similar 
security guards.

Issues included in this patch are listed in the [JJWT 0.11.3 milestone](https://github.com/jwtk/jjwt/milestone/24).

#### Backwards Compatibility Warning

In addition to additional protections against 
[r or s values of zero in ECDSA signatures](https://neilmadden.blog/2022/04/19/psychic-signatures-in-java/), this 
release also disables by default legacy DER-encoded signatures that might be included in an ECDSA-signed JWT. 
(DER-encoded signatures are not supported by the JWT RFC specifications, so they are not frequently encountered.)

However, if you are using an application that needs to consume such legacy JWTs (either produced by a very 
early version of JJWT, or a different JWT library), you may re-enable DER-encoded ECDSA signatures by setting the 
`io.jsonwebtoken.impl.crypto.EllipticCurveSignatureValidator.derEncodingSupported` System property to the _exact_ 
`String` value `true`.  For example:

```java
System.setProperty("io.jsonwebtoken.impl.crypto.EllipticCurveSignatureValidator.derEncodingSupported", "true");
```

*BUT BE CAREFUL*:  **DO NOT** set this System property if your application may run on one of the vulnerable JVMs
noted above (Java SE versions 15-15.0.6, 17-17.0.2, and 18).

You may safely set this property to a `String` value of `true` on all other versions of the JVM if you need to 
support these legacy JWTs, *otherwise it is best to ignore (not set) the property entirely*.

#### Credits

Thank you to [Neil Madden](https://neilmadden.blog), the security researcher that first discovered the JVM
vulnerability as covered in his [Psychic Signatures in Java](https://neilmadden.blog/2022/04/19/psychic-signatures-in-java/) blog post.

We'd also like to thank Toshiki Sasazaki, a member of [LINE Corporation](https://linecorp.com)'s Application Security 
Team as the first person to report the concern directly to the JJWT team, as well as for working with us during testing 
leading to our conclusions and subsequent 0.11.3 patch release.

### 0.11.2

This patch release:

* Allows empty JWS bodies to support [RFC 8555](https://tools.ietf.org/html/rfc8555) and similar initiatives. [Pull Request 540](https://github.com/jwtk/jjwt/pull/540)
* Ensures OSGi environments can access JJWT implementation bundles (`jjwt-jackson`, `jjwt-gson`, etc) as fragments to `jjwt-api` bundle. [Pull Request 580](https://github.com/jwtk/jjwt/pull/580)
* Rejects `allowedClockSkewSeconds` values that would cause numeric overflow. [Issue 583](https://github.com/jwtk/jjwt/issues/583) 
* Upgrades Jackson dependency to version `2.9.10.4` to address all known Jackson CVE vulnerabilities. [Issue 585](https://github.com/jwtk/jjwt/issues/585)
* Updates `SecretKey` algorithm name validation to allow PKCS12 KeyStore OIDs in addition to JCA Names. [Issue 588](https://github.com/jwtk/jjwt/issues/588)
* Enabled CI builds on JDK 14. [Pull Request 590](https://github.com/jwtk/jjwt/pull/590)
* Adds missing parameters type to `Maps.add()`, which removes an unchecked type warning. [Issue 591](https://github.com/jwtk/jjwt/issues/591)
* Ensures `GsonDeserializer` always uses `UTF-8` for encoding bytes to Strings. [Pull Request 592](https://github.com/jwtk/jjwt/pull/592)

All issues and PRs are listed in the Github [JJWT 0.11.2 milestone](https://github.com/jwtk/jjwt/milestone/23?closed=1).


### 0.11.1

This patch release:

* Upgrades the `jjwt-jackson` module's Jackson dependency to `2.9.10.3`.
* Fixes an issue when using Java 9+ `Map.of` with `JacksonDeserializer` that resulted in an `NullPointerException`.
* Fixes an issue that prevented the `jjwt-gson` .jar's seralizer/deserializer implementation from being detected automatically.
* Ensures service implementations are now loaded from the context class loader, Services.class.classLoader, and the system classloader, the first classloader with a service wins, and the others are ignored. This mimics how `Classes.forName()` works, and how JJWT attempted to auto-discover various implementations in previous versions.
* Fixes a minor error in the `Claims#getIssuedAt` JavaDoc.

### 0.11.0

This minor release:

* Adds [Google's Gson](https://github.com/google/gson) as a natively supported JSON parser. Installation instructions 
  have been updated and new [JJWT Gson usage guidelines](https://github.com/jwtk/jjwt#json-gson) have been added.
* Updates the Jackson dependency version to [2.9.10](https://github.com/FasterXML/jackson/wiki/Jackson-Release-2.9#patches)
to address three security vulnerabilities in Jackson.
* A new `JwtParserBuilder` interface has been added and is the recommended way of creating an immutable and thread-safe JwtParser instance.  Mutable methods in `JwtParser` will be removed before v1.0.
    Migration to the new signatures is straightforward, for example:
    
    Previous Version:
    ```java 
     Jwts.parser()
         .requireAudience("string")
         .parse(jwtString)
    ```
    Current Version:
    ```java
    Jwts.parserBuilder()
        .requireAudience("string")
        .build()
        .parse(jwtString)
    ```
* Adds `io.jsonwebtoken.lang.Maps` utility class to make creation of maps fluent, as demonstrated next.
* Adds support for custom types when deserializing with Jackson. To use configure your parser:
    ```java
    Jwts.parserBuilder().deserializeJsonWith(
        new JacksonDeserializer(
            Maps.of("claimName", YourType.class).build() // <--
        )
    ).build()
  ```
* Moves JSON Serializer/Deserializer implementations to a different package name.
  - `io.jsonwebtoken.io.JacksonSerializer` -> `io.jsonwebtoken.jackson.io.JacksonSerializer`
  - `io.jsonwebtoken.io.JacksonDeserializer` -> `io.jsonwebtoken.jackson.io.JacksonDeserializer`
  - `io.jsonwebtoken.io.OrgJsonSerializer` -> `io.jsonwebtoken.orgjson.io.OrgJsonSerializer`
  - `io.jsonwebtoken.io.OrgJsonDeserializer` -> `io.jsonwebtoken.orgjson.io.OrgJsonDeserializer`

  A backward compatibility modules has been created using the `deprecated` classifier (`io.jsonwebtoken:jjwt-jackson:0.11.0:deprecated` and `io.jsonwebtoken:jjwt-orjson:0.11.0:deprecated`), if you are compiling against these classes directly, otherwise you will be unaffected.

#### Backwards Compatibility Warning

Due to this package move, if you are currently using one of the above four existing (pre 0.11.0) classes with `compile` scope, you must either:
  1. change your code to use the newer package classes (recommended), or 
  1. change your build/dependency configuration to use the `deprecated` dependency classifier to use the existing classes, as follows:
      
**Maven**

```xml
<dependency>
    <groupId>io.jsonwebtoken</groupId>
    <artifactId>jjwt-jackson</artifactId>
    <version>0.11.0</version>
    <classifier>deprecated</classifier>
    <scope>compile</scope>
</dependency>
```

**Gradle**

```groovy
compile 'io.jsonwebtoken:jjwt-jackson:0.11.0:deprecated'
```

**Note:** that the first option is recommended since the second option will not be available starting with the 1.0 release.

### 0.10.8

This patch release:

* Ensures that SignatureAlgorithms `PS256`, `PS384`, and `PS512` work properly on JDK 11 and later without the need
  for BouncyCastle.  Previous releases referenced a BouncyCastle-specific 
  algorithm name instead of the Java Security Standard Algorithm Name of 
  [`RSASSA-PSS`](https://docs.oracle.com/en/java/javase/11/docs/specs/security/standard-names.html#signature-algorithms).
  This release ensures the standard name is used moving forward.
  
* Fixes a backwards-compatibility [bug](https://github.com/jwtk/jjwt/issues/536) when parsing compressed JWTs 
  created from 0.10.6 or earlier using the `DEFLATE` compression algorithm.  

### 0.10.7

This patch release:
 
* Adds a new [Community section](https://github.com/jwtk/jjwt#community) in the documentation discussing asking 
  questions, using Slack and Gittr, and opening new issues and pull requests. 
* Fixes a [memory leak](https://github.com/jwtk/jjwt/issues/392) found in the DEFLATE compression 
codec implementation.
* Updates the Jackson dependency version to [2.9.9.1](https://github.com/FasterXML/jackson/wiki/Jackson-Release-2.9#patches)
to address three security vulnerabilities in Jackson:
[CVE-2019-12086](https://nvd.nist.gov/vuln/detail/CVE-2019-12086),
[CVE-2019-12384](https://nvd.nist.gov/vuln/detail/CVE-2019-12384), and
[CVE-2019-12814](https://nvd.nist.gov/vuln/detail/CVE-2019-12814).
* Fixes a [bug](https://github.com/jwtk/jjwt/issues/397) when Jackson is in the classpath but the `jjwt-jackson` .jar is not.
* Fixes various documentation and typo fixes.

### 0.10.6

This patch release updates the jackson-databind version to 2.9.8 to address a critical security vulnerability in that
library.

### 0.10.5

This patch release fixed an Android `org.json` library compatibility [issue](https://github.com/jwtk/jjwt/issues/388).

### 0.10.4

This patch release fixed an [outstanding issue](https://github.com/jwtk/jjwt/issues/381) with JCA name 
case-sensitivity that impacted Android that was not caught in the 0.10.3 release.

### 0.10.3

This is a minor patch release that fixed a key length assertion for `SignatureAlgorithm.forSigningKey` that was 
failing in Android environments.  The Android dependencies and ProGuard exclusions documentation was updated as 
well to reflect Android Studio 3.0 conventions.

### 0.10.2

This is a minor patch release that ensures the `OrgJsonSerializer` and `OrgJsonDeserializer` implementations are 
compatible with Android's older `org.json` API.  Previously JJWT used newer `org.json` APIs that are not 
available on Android.

### 0.10.1

This is a minor point release that ensures the BouncyCastle dependency is optional and not pulled in as a transitive
dependency into projects.
 
Internal implementation code (not impacting the JJWT API) and documentation was also updated to reflect that all 
Elliptic Curve algorithms are standard on the JDK and do not require Bouncy Castle.

Bouncy Castle is only needed when using PS256, PS384, and PS512 signature algorithms on < JDK 11. 
[JDK 11 and later](https://bugs.openjdk.java.net/browse/JDK-8146293) supports these algorithms natively.

### 0.10.0

This is a fairly large feature enhancement release that enables the following:

* Modular project structure resulting in pluggable JJWT dependencies ([Issue 348](https://github.com/jwtk/jjwt/issues/348))
* Auto-configuration for Jackson or JSON-Java [JSON processors](https://github.com/jwtk/jjwt#json).
* [Automatic SignatureAlgorithm selection](https://github.com/jwtk/jjwt#jws-create-key) based on specified signing Key.
* Algorithm and Key [Strength Assertions](https://github.com/jwtk/jjwt#jws-key)
* [Simplified Key generation](https://github.com/jwtk/jjwt#jws-key-create)
* Deterministic [Base64(URL) support](https://github.com/jwtk/jjwt#base64) on all JDK and Android platforms
* [Custom JSON processing](https://github.com/jwtk/jjwt#json-custom)
* Complete [documentation](https://github.com/jwtk/jjwt)
* and a bunch of other [minor fixes and enhancements](https://github.com/jwtk/jjwt/milestone/11).

**BACKWARDS-COMPATIBILITY NOTICE:**

JJWT's new modular design utilizes distinctions between compile and runtime dependencies to ensure you only depend
on the public APIs that are safe to use in your application.  All internal/private implementation classes have
been moved to a new `jjwt-impl` runtime dependency.

If you depended on any internal implementation classes in the past, you have two choices:

1. Refactor your code to use the public-only API classes and interfaces in the `jjwt-api` .jar.  Any functionality
   you might have used in the internal implementation should be available via newer cleaner interfaces and helper 
   classes in that .jar.
   
2. Specify the new `jjwt-impl` .jar not as a runtime dependency but as a compile dependency.  This would make your
   upgrade to JJWT 0.10.0 fully backwards compatible, but you do so _at your own risk_.  JJWT will make **NO** 
   semantic version compatibility guarantees in the `jjwt-impl` .jar moving forward.  Semantic versioning will be 
   very carefully adhered to in all other JJWT dependencies however.

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
    // the sub claim was missing or did not have a 'jsmith' value
}
```

If it is important to react to a missing vs an incorrect value, instead of catching `InvalidClaimException`, you can catch either `MissingClaimException` or `IncorrectClaimException`:

```java
try {
    Jwts.parser().requireSubject("jsmith").setSigningKey(key).parseClaimsJws(s);
} catch(MissingClaimException mce) {
    // the parsed JWT did not have the sub claim
} catch(IncorrectClaimException ice) {
    // the parsed JWT had a sub claim, but its value was not equal to 'jsmith'
}
```

You can also require custom claims by using the `require(claimName, requiredValue)` method - for example:

```java
try {
    Jwts.parser().require("myClaim", "myRequiredValue").setSigningKey(key).parseClaimsJws(s);
} catch(InvalidClaimException ice) {
    // the 'myClaim' claim was missing or did not have a 'myRequiredValue' value
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

This will set a new `zip` header with the name of the compression algorithm used so that parsers can see that value and decompress accordingly.

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

You will then need to specify a `CompressionCodecResolver` on the parser, so you can inspect the `zip` header and return your custom codec when discovered:

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

The signature is still validated, and the JWT instance will still not be returned if the jwt string is invalid, as 
expected.  You just get to 'see' the JWT data for key discovery before the parser validates.  Nice.

This of course requires that you put some sort of information in the JWS when you create it so that your 
`SigningKeyResolver` implementation can look at it later and look up the key.  The *standard* way to do this is to 
use the JWS `kid` ('key id') header parameter, for example:

```java
Jwts.builder().setHeaderParam("kid", your_signing_key_id_NOT_THE_SECRET).build();
```

You could of course set any other header parameter or claims instead of setting `kid` if you want - 
that's just the default parameter reserved for signing key identification.  If you can locate the signing key based 
on other information in the header or claims, you don't need to set the `kid` parameter - just make sure your 
resolver implementation knows how to look up the key.

Finally, a nice `SigningKeyResolverAdapter` is provided to allow you to write quick and simple subclasses or 
anonymous classes instead of having to implement the `SigningKeyResolver` interface directly.  For example:

```java
Jws<Claims> jws = Jwts.parser().setSigningKeyResolver(new SigningKeyResolverAdapter() {
        @Override
        public byte[] resolveSigningKeyBytes(JwsHeader header, Claims claims) {
            //inspect the header or claims, lookup and return the signing key
            String keyId = header.getKeyId(); //or any other parameter that you need to inspect
            return getSigningKey(keyId); //implement me
        }})
    .parseClaimsJws(compact);
```

### 0.3

- [Issue 6](https://github.com/jwtk/jjwt/issues/6): Parsing an expired Claims JWT or JWS (as determined by the `exp` 
  claim) will now throw an `ExpiredJwtException`.
- [Issue 7](https://github.com/jwtk/jjwt/issues/7): Parsing a premature Claims JWT or JWS (as determined by the `nbf`
  claim) will now throw a `PrematureJwtException`.

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
