package io.jsonwebtoken.security

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
        assertEquals 13, KeyAlgorithms.values().size()
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
                contains(KeyAlgorithms.RSA_OAEP_256)
        )
    }

    @Test
    void testFindByExactId() {
        assertSame KeyAlgorithms.A128KW, KeyAlgorithms.findById('A128KW')
    }

    @Test
    void testFindByIdCaseInsensitive() {
        assertSame KeyAlgorithms.A128GCMKW, KeyAlgorithms.findById('a128GcMkW')
    }
}
