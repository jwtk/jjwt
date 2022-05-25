package io.jsonwebtoken.security


import org.junit.Test

import static org.junit.Assert.assertNull
import static org.junit.Assert.assertSame

class SignatureAlgorithmsTest {

    @Test
    void testPrivateCtor() { // for code coverage only
        new SignatureAlgorithms()
    }

    @Test
    void testForId() {
        for (SignatureAlgorithm alg : SignatureAlgorithms.values()) {
            assertSame alg, SignatureAlgorithms.forId(alg.getId())
        }
    }

    @Test
    void testForIdCaseInsensitive() {
        for (SignatureAlgorithm alg : SignatureAlgorithms.values()) {
            assertSame alg, SignatureAlgorithms.forId(alg.getId().toLowerCase())
        }
    }

    @Test(expected = IllegalArgumentException)
    void testForIdWithInvalidId() {
        //unlike the 'find' paradigm, 'for' requires the value to exist
        SignatureAlgorithms.forId('invalid')
    }

    @Test
    void testFindById() {
        for (SignatureAlgorithm alg : SignatureAlgorithms.values()) {
            assertSame alg, SignatureAlgorithms.findById(alg.getId())
        }
    }

    @Test
    void testFindByIdCaseInsensitive() {
        for (SignatureAlgorithm alg : SignatureAlgorithms.values()) {
            assertSame alg, SignatureAlgorithms.findById(alg.getId().toLowerCase())
        }
    }

    @Test
    void testFindByIdWithInvalidId() {
        // 'find' paradigm can return null if not found
        assertNull SignatureAlgorithms.findById('invalid')
    }
}
