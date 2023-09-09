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
import io.jsonwebtoken.security.Curve;
import io.jsonwebtoken.security.EcPrivateJwk;
import io.jsonwebtoken.security.EcPublicJwk;
import io.jsonwebtoken.security.Jwk;
import io.jsonwebtoken.security.Jwks;
import io.jsonwebtoken.security.KeyAlgorithm;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.MacAlgorithm;
import io.jsonwebtoken.security.OctetPrivateJwk;
import io.jsonwebtoken.security.OctetPublicJwk;
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
import java.util.Set;

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
        MacAlgorithm alg = Jwts.SIG.HS512; //or HS384 or HS256
        SecretKey key = alg.key().build();

        String message = "Hello World!";
        byte[] content = message.getBytes(StandardCharsets.UTF_8);

        // Create the compact JWS:
        String jws = Jwts.builder().content(content, "text/plain").signWith(key, alg).compact();

        // Parse the compact JWS:
        content = Jwts.parser().verifyWith(key).build().parseContentJws(jws).getPayload();

        assert message.equals(new String(content, StandardCharsets.UTF_8));
    }

    /**
     * {@code README.md#example-jws-rsa}
     */
    @Test
    public void testExampleJwsRSA() {
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
    }

    /**
     * {@code README.md#example-jws-ecdsa}
     */
    @Test
    public void testExampleJwsECDSA() {
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
    }

    /**
     * {@code README.md#example-jws-eddsa}
     */
    @Test
    public void testExampleJwsEdDSA() {
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
    }

    /**
     * {@code README.md#example-jwe-dir}
     */
    @Test
    public void testExampleJweDir() {
        // Create a test key suitable for the desired payload encryption algorithm:
        // (A*GCM algorithms are recommended, but require JDK 8 or later)
        AeadAlgorithm enc = Jwts.ENC.A256GCM; //or A128GCM, A192GCM, A256CBC-HS512, etc...
        SecretKey key = enc.key().build();

        String message = "Live long and prosper.";
        byte[] content = message.getBytes(StandardCharsets.UTF_8);

        // Create the compact JWE:
        String jwe = Jwts.builder().content(content, "text/plain").encryptWith(key, enc).compact();

        // Parse the compact JWE:
        content = Jwts.parser().decryptWith(key).build().parseContentJwe(jwe).getPayload();

        assert message.equals(new String(content, StandardCharsets.UTF_8));
    }

    /**
     * {@code README.md#example-jwe-rsa}
     */
    @Test
    public void testExampleJweRSA() {
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
        Set<String> audience = Jwts.parser()
                .decryptWith(pair.getPrivate()) // <-- Alice's RSA private key
                .build().parseClaimsJwe(jwe).getPayload().getAudience();

        assert audience.contains("Alice");
    }

    /**
     * {@code README.md#example-jwe-aeskw}
     */
    @Test
    public void testExampleJweAESKW() {
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
    }

    /**
     * {@code README.md#example-jwe-ecdhes}
     */
    @Test
    public void testExampleJweECDHES() {
        // Create a test KeyPair suitable for the desired EC key algorithm:
        KeyPair pair = Jwts.SIG.ES512.keyPair().build();

        // Choose the key algorithm used encrypt the payload key:
        KeyAlgorithm<PublicKey, PrivateKey> alg = Jwts.KEY.ECDH_ES_A256KW; //ECDH_ES_A192KW, etc...
        // Choose the Encryption Algorithm to encrypt the payload:
        AeadAlgorithm enc = Jwts.ENC.A256GCM; //or A192GCM, A128GCM, A256CBC-HS512, etc...

        // Bob creates the compact JWE with Alice's EC public key so only she may read it:
        String jwe = Jwts.builder().audience("Alice")
                .encryptWith(pair.getPublic(), alg, enc) // <-- Alice's EC public key
                .compact();

        // Alice receives and decrypts the compact JWE:
        Set<String> audience = Jwts.parser()
                .decryptWith(pair.getPrivate()) // <-- Alice's EC private key
                .build().parseClaimsJwe(jwe).getPayload().getAudience();

        assert audience.contains("Alice");
    }

    /**
     * {@code README.md#example-jwe-password}
     */
    @Test
    public void testExampleJwePassword() {
        //DO NOT use this example password in a real app, it is well-known to password crackers
        String pw = "correct horse battery staple";
        Password password = Keys.password(pw.toCharArray());

        // Choose the desired PBES2 key derivation algorithm:
        KeyAlgorithm<Password, Password> alg = Jwts.KEY.PBES2_HS512_A256KW; //or PBES2_HS384...

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
    }

    @SuppressWarnings({"unchecked", "rawtypes"})
    @Test
    public void testExampleSecretJwk() {
        SecretKey key = Jwts.SIG.HS512.key().build(); // or HS384 or HS256
        SecretJwk jwk = builder().key(key).idFromThumbprint().build();

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
        RSAPublicKey key = (RSAPublicKey) Jwts.SIG.RS512.keyPair().build().getPublic();
        RsaPublicJwk jwk = builder().key(key).idFromThumbprint().build();

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
        KeyPair pair = Jwts.SIG.RS512.keyPair().build();
        RSAPublicKey pubKey = (RSAPublicKey) pair.getPublic();
        RSAPrivateKey privKey = (RSAPrivateKey) pair.getPrivate();

        RsaPrivateJwk privJwk = builder().key(privKey).idFromThumbprint().build();
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
        ECPublicKey key = (ECPublicKey) Jwts.SIG.ES512.keyPair().build().getPublic();
        EcPublicJwk jwk = builder().key(key).idFromThumbprint().build();

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
        KeyPair pair = Jwts.SIG.ES512.keyPair().build();
        ECPublicKey pubKey = (ECPublicKey) pair.getPublic();
        ECPrivateKey privKey = (ECPrivateKey) pair.getPrivate();

        EcPrivateJwk privJwk = builder().key(privKey).idFromThumbprint().build();
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

    @SuppressWarnings({"unchecked", "rawtypes"})
    @Test
    public void testExampleEdEcPublicJwk() {
        PublicKey key = Jwks.CRV.Ed25519.keyPair().build().getPublic(); // or Ed448, X25519, X448
        OctetPublicJwk<PublicKey> jwk = builder().octetKey(key).idFromThumbprint().build();

        assert jwk.getId().equals(jwk.thumbprint().toString());
        assert key.equals(jwk.toKey());

        byte[] utf8Bytes = new JacksonSerializer().serialize(jwk); // or GsonSerializer(), etc
        String jwkJson = new String(utf8Bytes, StandardCharsets.UTF_8);
        Jwk<?> parsed = Jwks.parser().build().parse(jwkJson);

        assert parsed instanceof OctetPublicJwk;
        assert jwk.equals(parsed);
    }

    @SuppressWarnings({"unchecked", "rawtypes"})
    @Test
    public void testExampleEdEcPrivateJwk() {
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
