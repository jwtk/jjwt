package io.jsonwebtoken.impl.security

import io.jsonwebtoken.security.HashAlgorithm
import org.junit.Test

import java.nio.charset.StandardCharsets

import static org.junit.Assert.assertTrue

class DefaultHashAlgorithmTest {

    static final def algs = [DefaultHashAlgorithm.SHA1, DefaultHashAlgorithm.SHA256]

    @Test
    void testDigestAndVerify() {
        byte[] data = "Hello World".getBytes(StandardCharsets.UTF_8)
        for(HashAlgorithm alg : algs) {
            byte[] hash = alg.digest(new DefaultRequest<byte[]>(data, null, null))
            assertTrue alg.verify(new DefaultVerifyDigestRequest(data, null, null, hash))
        }
    }
}
