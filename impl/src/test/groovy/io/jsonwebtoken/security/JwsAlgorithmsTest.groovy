package io.jsonwebtoken.security

import org.junit.Test

import static org.junit.Assert.assertNull
import static org.junit.Assert.assertSame

class JwsAlgorithmsTest {

    @Test
    void testPrivateCtor() { // for code coverage only
        new JwsAlgorithms()
    }

    @Test
    void testForId() {
        for (SecureDigestAlgorithm alg : JwsAlgorithms.values()) {
            assertSame alg, JwsAlgorithms.forId(alg.getId())
        }
    }

    @Test
    void testForIdCaseInsensitive() {
        for (SecureDigestAlgorithm alg : JwsAlgorithms.values()) {
            assertSame alg, JwsAlgorithms.forId(alg.getId().toLowerCase())
        }
    }

    @Test(expected = IllegalArgumentException)
    void testForIdWithInvalidId() {
        //unlike the 'find' paradigm, 'for' requires the value to exist
        JwsAlgorithms.forId('invalid')
    }

    @Test
    void testFindById() {
        for (SecureDigestAlgorithm alg : JwsAlgorithms.values()) {
            assertSame alg, JwsAlgorithms.findById(alg.getId())
        }
    }

    @Test
    void testFindByIdCaseInsensitive() {
        for (SecureDigestAlgorithm alg : JwsAlgorithms.values()) {
            assertSame alg, JwsAlgorithms.findById(alg.getId().toLowerCase())
        }
    }

    @Test
    void testFindByIdWithInvalidId() {
        // 'find' paradigm can return null if not found
        assertNull JwsAlgorithms.findById('invalid')
    }
}
