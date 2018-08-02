package io.jsonwebtoken.security

import static org.junit.Assert.*
import org.junit.Test

class SignatureAlgorithmsTest {

    @Test
    void testPrivateCtor() {
        new SignatureAlgorithms() // for code coverage only
    }

    @Test
    void testForNameCaseInsensitive() {
        for(SignatureAlgorithm alg : SignatureAlgorithms.STANDARD_ALGORITHMS.values()) {
            assertSame alg, SignatureAlgorithms.forName(alg.getName().toLowerCase())
        }
    }
}
