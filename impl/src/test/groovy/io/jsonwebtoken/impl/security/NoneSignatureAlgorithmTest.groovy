package io.jsonwebtoken.impl.security

import io.jsonwebtoken.security.SignatureException
import org.junit.Before
import org.junit.Test

import static org.junit.Assert.assertEquals
import static org.junit.Assert.assertTrue

class NoneSignatureAlgorithmTest {

    private NoneSignatureAlgorithm alg

    @Before
    void setUp() {
        this.alg = new NoneSignatureAlgorithm()
    }

    @Test
    void testName() {
        assertEquals "none", alg.getId();
    }

    @Test(expected = SignatureException)
    void testSign() {
        alg.sign(null)
    }

    @Test(expected = SignatureException)
    void testVerify() {
        alg.verify(null)
    }

    @Test
    void testHashCode() {
        assertEquals 'none'.hashCode(), alg.hashCode()
    }

    @Test
    void testEquals() {
        assertTrue alg.equals(new NoneSignatureAlgorithm())
    }

    @Test
    void testIdentityEquals() {
        assertTrue alg.equals(alg)
    }

    @Test
    void testToString() {
        assertEquals alg.getId(), alg.toString()
    }
}
