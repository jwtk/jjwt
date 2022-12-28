package io.jsonwebtoken;

import io.jsonwebtoken.security.AeadAlgorithm;
import io.jsonwebtoken.security.AsymmetricKeySignatureAlgorithm;
import io.jsonwebtoken.security.EncryptionAlgorithms;
import io.jsonwebtoken.security.KeyAlgorithm;
import io.jsonwebtoken.security.KeyAlgorithms;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.Password;
import io.jsonwebtoken.security.SecretKeyAlgorithm;
import io.jsonwebtoken.security.SecretKeySignatureAlgorithm;
import io.jsonwebtoken.security.SignatureAlgorithms;
import org.junit.Test;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

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
        SecretKeySignatureAlgorithm alg = SignatureAlgorithms.HS512; //or HS256 or HS384
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
        AsymmetricKeySignatureAlgorithm alg = SignatureAlgorithms.RS512; //or PS512, RS256, etc...
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
        AsymmetricKeySignatureAlgorithm alg = SignatureAlgorithms.ES512; //or ES256 or ES384
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
        AeadAlgorithm enc = EncryptionAlgorithms.A256GCM; //or A128GCM, A192GCM, A256CBC-HS512, etc...
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
        KeyPair pair = SignatureAlgorithms.RS512.keyPairBuilder().build();

        // Choose the key algorithm used encrypt the payload key:
        KeyAlgorithm<PublicKey, PrivateKey> alg = KeyAlgorithms.RSA_OAEP_256; //or RSA_OAEP or RSA1_5
        // Choose the Encryption Algorithm to encrypt the payload:
        AeadAlgorithm enc = EncryptionAlgorithms.A256GCM; //or A192GCM, A128GCM, A256CBC-HS512, etc...

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
        SecretKeyAlgorithm alg = KeyAlgorithms.A256GCMKW; //or A192GCMKW, A128GCMKW, A256KW, etc...
        SecretKey key = alg.keyBuilder().build();

        // Chooose the Encryption Algorithm used to encrypt the payload:
        AeadAlgorithm enc = EncryptionAlgorithms.A256GCM; //or A192GCM, A128GCM, A256CBC-HS512, etc...

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
        KeyPair pair = SignatureAlgorithms.ES512.keyPairBuilder().build();

        // Choose the key algorithm used encrypt the payload key:
        KeyAlgorithm<PublicKey, PrivateKey> alg = KeyAlgorithms.ECDH_ES_A256KW; //ECDH_ES_A192KW, etc...
        // Choose the Encryption Algorithm to encrypt the payload:
        AeadAlgorithm enc = EncryptionAlgorithms.A256GCM; //or A192GCM, A128GCM, A256CBC-HS512, etc...

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
        KeyAlgorithm<Password, Password> alg = KeyAlgorithms.PBES2_HS512_A256KW; //or PBES2_HS384_A192KW or PBES2_HS256_A128KW

        // Optionally choose the number of PBES2 computational iterations to use to derive the key.
        // This is optional - if you do not specify a value, JJWT will automatically choose a value
        // based on your chosen PBES2 algorithm and OWASP PBKDF2 recommendations here:
        // https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#pbkdf2
        //
        // If you do specify a value, ensure the iterations are large enough for your desired alg
        //int pbkdf2Iterations = 120000; //for HS512. Needs to be much higher for smaller hash algs.

        // Choose the Encryption Algorithm used to encrypt the payload:
        AeadAlgorithm enc = EncryptionAlgorithms.A256GCM; //or A192GCM, A128GCM, A256CBC-HS512, etc...

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
}
