/*
 * Copyright (C) 2022 jsonwebtoken.io
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.jsonwebtoken.all;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.jackson.io.JacksonSerializer;
import io.jsonwebtoken.security.AeadAlgorithm;
import io.jsonwebtoken.security.Algorithms;
import io.jsonwebtoken.security.EcPrivateJwk;
import io.jsonwebtoken.security.EcPublicJwk;
import io.jsonwebtoken.security.Jwk;
import io.jsonwebtoken.security.Jwks;
import io.jsonwebtoken.security.JwsAlgorithms;
import io.jsonwebtoken.security.KeyAlgorithm;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.MacAlgorithm;
import io.jsonwebtoken.security.Password;
import io.jsonwebtoken.security.RsaPrivateJwk;
import io.jsonwebtoken.security.RsaPublicJwk;
import io.jsonwebtoken.security.SecretJwk;
import io.jsonwebtoken.security.SecretKeyAlgorithm;
import io.jsonwebtoken.security.SignatureAlgorithm;
import org.junit.Test;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import static io.jsonwebtoken.security.Jwks.builder;

/**
 * Test cases to ensure snippets in README.md work/compile as expected with the Java language (not Groovy):
 *
 * @since JJWT_RELEASE_VERSION
 */
public class JavaReadmeTest {

    /**
     * {@code README.md#example-jws-hs}
     */
    @Test
    public void testExampleJwsHS() {
        // Create a test key suitable for the desired HMAC-SHA algorithm:
        MacAlgorithm alg = JwsAlgorithms.HS512; //or HS256 or HS384
        SecretKey key = alg.keyBuilder().build();

        String message = "Hello World!";
        byte[] content = message.getBytes(StandardCharsets.UTF_8);

        // Create the compact JWS:
        String jws = Jwts.builder().setContent(content, "text/plain").signWith(key, alg).compact();

        // Parse the compact JWS:
        content = Jwts.parserBuilder().verifyWith(key).build().parseContentJws(jws).getPayload();

        assert message.equals(new String(content, StandardCharsets.UTF_8));
    }

    /**
     * {@code README.md#example-jws-rsa}
     */
    @Test
    public void testExampleJwsRSA() {
        // Create a test key suitable for the desired RSA signature algorithm:
        SignatureAlgorithm alg = JwsAlgorithms.RS512; //or PS512, RS256, etc...
        KeyPair pair = alg.keyPairBuilder().build();

        // Bob creates the compact JWS with his RSA private key:
        String jws = Jwts.builder().setSubject("Alice")
                .signWith(pair.getPrivate(), alg) // <-- Bob's RSA private key
                .compact();

        // Alice receives and verifies the compact JWS came from Bob:
        String subject = Jwts.parserBuilder()
                .verifyWith(pair.getPublic()) // <-- Bob's RSA public key
                .build().parseClaimsJws(jws).getPayload().getSubject();

        assert "Alice".equals(subject);
    }

    /**
     * {@code README.md#example-jws-ecdsa}
     */
    @Test
    public void testExampleJwsECDSA() {
        // Create a test key suitable for the desired ECDSA signature algorithm:
        SignatureAlgorithm alg = JwsAlgorithms.ES512; //or ES256 or ES384
        KeyPair pair = alg.keyPairBuilder().build();

        // Bob creates the compact JWS with his EC private key:
        String jws = Jwts.builder().setSubject("Alice")
                .signWith(pair.getPrivate(), alg) // <-- Bob's EC private key
                .compact();

        // Alice receives and verifies the compact JWS came from Bob:
        String subject = Jwts.parserBuilder()
                .verifyWith(pair.getPublic()) // <-- Bob's EC public key
                .build().parseClaimsJws(jws).getPayload().getSubject();

        assert "Alice".equals(subject);
    }

    /**
     * {@code README.md#example-jwe-dir}
     */
    @Test
    public void testExampleJweDir() {
        // Create a test key suitable for the desired payload encryption algorithm:
        // (A*GCM algorithms are recommended, but require JDK 8 or later)
        AeadAlgorithm enc = Algorithms.enc.A256GCM; //or A128GCM, A192GCM, A256CBC-HS512, etc...
        SecretKey key = enc.keyBuilder().build();

        String message = "Live long and prosper.";
        byte[] content = message.getBytes(StandardCharsets.UTF_8);

        // Create the compact JWE:
        String jwe = Jwts.builder().setContent(content, "text/plain").encryptWith(key, enc).compact();

        // Parse the compact JWE:
        content = Jwts.parserBuilder().decryptWith(key).build().parseContentJwe(jwe).getPayload();

        assert message.equals(new String(content, StandardCharsets.UTF_8));
    }

    /**
     * {@code README.md#example-jwe-rsa}
     */
    @Test
    public void testExampleJweRSA() {
        // Create a test KeyPair suitable for the desired RSA key algorithm:
        KeyPair pair = JwsAlgorithms.RS512.keyPairBuilder().build();

        // Choose the key algorithm used encrypt the payload key:
        KeyAlgorithm<PublicKey, PrivateKey> alg = Algorithms.key.RSA_OAEP_256; //or RSA_OAEP or RSA1_5
        // Choose the Encryption Algorithm to encrypt the payload:
        AeadAlgorithm enc = Algorithms.enc.A256GCM; //or A192GCM, A128GCM, A256CBC-HS512, etc...

        // Bob creates the compact JWE with Alice's RSA public key so only she may read it:
        String jwe = Jwts.builder().setAudience("Alice")
                .encryptWith(pair.getPublic(), alg, enc) // <-- Alice's RSA public key
                .compact();

        // Alice receives and decrypts the compact JWE:
        String audience = Jwts.parserBuilder()
                .decryptWith(pair.getPrivate()) // <-- Alice's RSA private key
                .build().parseClaimsJwe(jwe).getPayload().getAudience();

        assert "Alice".equals(audience);
    }

    /**
     * {@code README.md#example-jwe-aeskw}
     */
    @Test
    public void testExampleJweAESKW() {
        // Create a test SecretKey suitable for the desired AES Key Wrap algorithm:
        SecretKeyAlgorithm alg = Algorithms.key.A256GCMKW; //or A192GCMKW, A128GCMKW, A256KW, etc...
        SecretKey key = alg.keyBuilder().build();

        // Chooose the Encryption Algorithm used to encrypt the payload:
        AeadAlgorithm enc = Algorithms.enc.A256GCM; //or A192GCM, A128GCM, A256CBC-HS512, etc...

        // Create the compact JWE:
        String jwe = Jwts.builder().setIssuer("me").encryptWith(key, alg, enc).compact();

        // Parse the compact JWE:
        String issuer = Jwts.parserBuilder().decryptWith(key).build()
                .parseClaimsJwe(jwe).getPayload().getIssuer();

        assert "me".equals(issuer);
    }

    /**
     * {@code README.md#example-jwe-ecdhes}
     */
    @Test
    public void testExampleJweECDHES() {
        // Create a test KeyPair suitable for the desired EC key algorithm:
        KeyPair pair = JwsAlgorithms.ES512.keyPairBuilder().build();

        // Choose the key algorithm used encrypt the payload key:
        KeyAlgorithm<PublicKey, PrivateKey> alg = Algorithms.key.ECDH_ES_A256KW; //ECDH_ES_A192KW, etc...
        // Choose the Encryption Algorithm to encrypt the payload:
        AeadAlgorithm enc = Algorithms.enc.A256GCM; //or A192GCM, A128GCM, A256CBC-HS512, etc...

        // Bob creates the compact JWE with Alice's EC public key so only she may read it:
        String jwe = Jwts.builder().setAudience("Alice")
                .encryptWith(pair.getPublic(), alg, enc) // <-- Alice's EC public key
                .compact();

        // Alice receives and decrypts the compact JWE:
        String audience = Jwts.parserBuilder()
                .decryptWith(pair.getPrivate()) // <-- Alice's EC private key
                .build().parseClaimsJwe(jwe).getPayload().getAudience();

        assert "Alice".equals(audience);
    }

    /**
     * {@code README.md#example-jwe-password}
     */
    @Test
    public void testExampleJwePassword() {
        //DO NOT use this example password in a real app, it is well-known to password crackers
        String pw = "correct horse battery staple";
        Password password = Keys.forPassword(pw.toCharArray());

        // Choose the desired PBES2 key derivation algorithm:
        KeyAlgorithm<Password, Password> alg = Algorithms.key.PBES2_HS512_A256KW; //or PBES2_HS384...

        // Optionally choose the number of PBES2 computational iterations to use to derive the key.
        // This is optional - if you do not specify a value, JJWT will automatically choose a value
        // based on your chosen PBES2 algorithm and OWASP PBKDF2 recommendations here:
        // https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#pbkdf2
        //
        // If you do specify a value, ensure the iterations are large enough for your desired alg
        //int pbkdf2Iterations = 120000; //for HS512. Needs to be much higher for smaller hash algs.

        // Choose the Encryption Algorithm used to encrypt the payload:
        AeadAlgorithm enc = Algorithms.enc.A256GCM; //or A192GCM, A128GCM, A256CBC-HS512, etc...

        // Create the compact JWE:
        String jwe = Jwts.builder().setIssuer("me")
                // Optional work factor is specified in the header:
                //.setHeader(Jwts.headerBuilder().setPbes2Count(pbkdf2Iterations).build())
                .encryptWith(password, alg, enc)
                .compact();

        // Parse the compact JWE:
        String issuer = Jwts.parserBuilder().decryptWith(password)
                .build().parseClaimsJwe(jwe).getPayload().getIssuer();

        assert "me".equals(issuer);
    }

    @SuppressWarnings({"unchecked", "rawtypes"})
    @Test
    public void testExampleSecretJwk() {
        SecretKey key = JwsAlgorithms.HS512.keyBuilder().build(); // or HS384 or HS256
        SecretJwk jwk = builder().forKey(key).setIdFromThumbprint().build();

        assert jwk.getId().equals(jwk.thumbprint().toString());
        assert key.equals(jwk.toKey());

        byte[] utf8Bytes = new JacksonSerializer().serialize(jwk); // or GsonSerializer(), etc
        String jwkJson = new String(utf8Bytes, StandardCharsets.UTF_8);
        Jwk<?> parsed = Jwks.parser().build().parse(jwkJson);

        assert parsed instanceof SecretJwk;
        assert jwk.equals(parsed);
    }

    @SuppressWarnings({"unchecked", "rawtypes"})
    @Test
    public void testExampleRsaPublicJwk() {
        RSAPublicKey key = (RSAPublicKey) JwsAlgorithms.RS512.keyPairBuilder().build().getPublic();
        RsaPublicJwk jwk = builder().forKey(key).setIdFromThumbprint().build();

        assert jwk.getId().equals(jwk.thumbprint().toString());
        assert key.equals(jwk.toKey());

        byte[] utf8Bytes = new JacksonSerializer().serialize(jwk); // or GsonSerializer(), etc
        String jwkJson = new String(utf8Bytes, StandardCharsets.UTF_8);
        Jwk<?> parsed = Jwks.parser().build().parse(jwkJson);

        assert parsed instanceof RsaPublicJwk;
        assert jwk.equals(parsed);
    }

    @SuppressWarnings({"unchecked", "rawtypes"})
    @Test
    public void testExampleRsaPrivateJwk() {
        KeyPair pair = JwsAlgorithms.RS512.keyPairBuilder().build();
        RSAPublicKey pubKey = (RSAPublicKey) pair.getPublic();
        RSAPrivateKey privKey = (RSAPrivateKey) pair.getPrivate();

        RsaPrivateJwk privJwk = builder().forKey(privKey).setIdFromThumbprint().build();
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
    }

    @SuppressWarnings({"unchecked", "rawtypes"})
    @Test
    public void testExampleEcPublicJwk() {
        ECPublicKey key = (ECPublicKey) JwsAlgorithms.ES512.keyPairBuilder().build().getPublic();
        EcPublicJwk jwk = builder().forKey(key).setIdFromThumbprint().build();

        assert jwk.getId().equals(jwk.thumbprint().toString());
        assert key.equals(jwk.toKey());

        byte[] utf8Bytes = new JacksonSerializer().serialize(jwk); // or GsonSerializer(), etc
        String jwkJson = new String(utf8Bytes, StandardCharsets.UTF_8);
        Jwk<?> parsed = Jwks.parser().build().parse(jwkJson);

        assert parsed instanceof EcPublicJwk;
        assert jwk.equals(parsed);
    }

    @SuppressWarnings({"unchecked", "rawtypes"})
    @Test
    public void testExampleEcPrivateJwk() {
        KeyPair pair = JwsAlgorithms.ES512.keyPairBuilder().build();
        ECPublicKey pubKey = (ECPublicKey) pair.getPublic();
        ECPrivateKey privKey = (ECPrivateKey) pair.getPrivate();

        EcPrivateJwk privJwk = builder().forKey(privKey).setIdFromThumbprint().build();
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
    }

    @Test
    public void testExampleJwkToString() {
        String json = "{\"kty\":\"oct\"," +
                "\"k\":\"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow\"," +
                "\"kid\":\"HMAC key used in https://www.rfc-editor.org/rfc/rfc7515#appendix-A.1.1 example.\"}";

        Jwk<?> jwk = Jwks.parser().build().parse(json);

        String expected = "{kty=oct, k=<redacted>, kid=HMAC key used in https://www.rfc-editor.org/rfc/rfc7515#appendix-A.1.1 example.}";
        assert expected.equals(jwk.toString());
    }
}
