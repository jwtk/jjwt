package io.jsonwebtoken;

import io.jsonwebtoken.security.SecretKeySignatureAlgorithm;
import io.jsonwebtoken.security.SignatureAlgorithms;
import org.junit.Test;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;

/**
 * Test cases to ensure snippets in README.md work/compile as expected.
 */
public class JavaReadmeTest {

    /**
     * Examples -> 'JWT Signed with HMAC'
     */
    @Test
    public void testJwtSignedWithHmac() {
        // Create a test key suitable for the desired HMAC-SHA algorithm:
        SecretKeySignatureAlgorithm alg = SignatureAlgorithms.HS256; //or HS384 or HS512
        SecretKey key = alg.keyBuilder().build();

        String message = "Hello World!";
        byte[] content = message.getBytes(StandardCharsets.UTF_8);

        // Create the compact JWS:
        String jws = Jwts.builder().setContent(content, "text/plain").signWith(key, alg).compact();

        // Parse the compact JWS:
        content = Jwts.parserBuilder().verifyWith(key).build().parseContentJws(jws).getPayload();

        assert message.equals(new String(content, StandardCharsets.UTF_8));
    }
}
