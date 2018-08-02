package io.jsonwebtoken.impl.security

import io.jsonwebtoken.security.SignatureException
import org.junit.Test

import static org.junit.Assert.assertEquals

class NoneSignatureAlgorithmTest {

    @Test
    void testName() {
        assertEquals "none", new NoneSignatureAlgorithm().getName();
    }

    @Test(expected = SignatureException)
    void testSign() {
        new NoneSignatureAlgorithm().sign(null)
    }

    @Test(expected = SignatureException)
    void testVerify() {
        new NoneSignatureAlgorithm().verify(null)
    }
}
