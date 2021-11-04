package io.jsonwebtoken.security

import io.jsonwebtoken.UnsupportedJwtException
import io.jsonwebtoken.impl.security.Pbes2HsAkwAlgorithm
import org.junit.Test

import java.security.Key

import static org.junit.Assert.*

class KeyAlgorithmsTest {

    @Test
    void testPrivateCtor() { //for code coverage only
        new KeyAlgorithms()
    }

    static boolean contains(KeyAlgorithm<? extends Key, ? extends Key> alg) {
        return KeyAlgorithms.values().contains(alg)
    }

    @Test
    void testValues() {
        assertEquals 17, KeyAlgorithms.values().size()
        assertTrue(contains(KeyAlgorithms.DIRECT) &&
                contains(KeyAlgorithms.A128KW) &&
                contains(KeyAlgorithms.A192KW) &&
                contains(KeyAlgorithms.A256KW) &&
                contains(KeyAlgorithms.A128GCMKW) &&
                contains(KeyAlgorithms.A192GCMKW) &&
                contains(KeyAlgorithms.A256GCMKW) &&
                contains(KeyAlgorithms.PBES2_HS256_A128KW) &&
                contains(KeyAlgorithms.PBES2_HS384_A192KW) &&
                contains(KeyAlgorithms.PBES2_HS512_A256KW) &&
                contains(KeyAlgorithms.RSA1_5) &&
                contains(KeyAlgorithms.RSA_OAEP) &&
                contains(KeyAlgorithms.RSA_OAEP_256) &&
                contains(KeyAlgorithms.ECDH_ES) &&
                contains(KeyAlgorithms.ECDH_ES_A128KW) &&
                contains(KeyAlgorithms.ECDH_ES_A192KW) &&
                contains(KeyAlgorithms.ECDH_ES_A256KW)
        )
    }

    @Test
    void testForId() {
        for (KeyAlgorithm alg : KeyAlgorithms.values()) {
            assertSame alg, KeyAlgorithms.forId(alg.getId())
        }
    }

    @Test
    void testForIdCaseInsensitive() {
        for (KeyAlgorithm alg : KeyAlgorithms.values()) {
            assertSame alg, KeyAlgorithms.forId(alg.getId().toLowerCase())
        }
    }

    @Test(expected = UnsupportedJwtException)
    void testForIdWithInvalidId() {
        //unlike the 'find' paradigm, 'for' requires the value to exist
        KeyAlgorithms.forId('invalid')
    }

    @Test
    void testFindById() {
        for (KeyAlgorithm alg : KeyAlgorithms.values()) {
            assertSame alg, KeyAlgorithms.findById(alg.getId())
        }
    }

    @Test
    void testFindByIdCaseInsensitive() {
        for (KeyAlgorithm alg : KeyAlgorithms.values()) {
            assertSame alg, KeyAlgorithms.findById(alg.getId().toLowerCase())
        }
    }

    @Test
    void testFindByIdWithInvalidId() {
        // 'find' paradigm can return null if not found
        assertNull KeyAlgorithms.findById('invalid')
    }

    @Test
    void testEstimateIterations() {
        // keep it super short so we don't hammer the test server or slow down the build too much:
        long desiredMillis = 50
        int result = KeyAlgorithms.estimateIterations(KeyAlgorithms.PBES2_HS256_A128KW, desiredMillis)
        assertTrue result > Pbes2HsAkwAlgorithm.MIN_RECOMMENDED_ITERATIONS
    }
}
