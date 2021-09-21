package io.jsonwebtoken.security

import org.junit.Test

import static org.junit.Assert.assertSame

class SignatureAlgorithmsTest {

    @Test
    void testPrivateCtor() {
        new SignatureAlgorithms() // for code coverage only
    }

    @Test
    void testForNameCaseInsensitive() {
        for(SignatureAlgorithm alg : SignatureAlgorithms.STANDARD_ALGORITHMS.values()) {
            assertSame alg, SignatureAlgorithms.forId(alg.getId().toLowerCase())
        }
    }
}
