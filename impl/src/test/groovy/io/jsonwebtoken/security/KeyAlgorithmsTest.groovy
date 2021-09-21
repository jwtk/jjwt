package io.jsonwebtoken.security

import org.junit.Test

import java.security.Key

import static org.junit.Assert.*

class KeyAlgorithmsTest {

    @Test
    void testPrivateCtor() { //for code coverage only
        new KeyAlgorithms()
    }

    static boolean contains(KeyAlgorithm<? extends Key,? extends Key> alg) {
        return KeyAlgorithms.values().contains(alg)
    }

    @Test
    void testValues() {
        assertEquals 7, KeyAlgorithms.values().size()
        assertTrue(contains(KeyAlgorithms.DIRECT) &&
                contains(KeyAlgorithms.A128KW) &&
                contains(KeyAlgorithms.A192KW) &&
                contains(KeyAlgorithms.A256KW) &&
                contains(KeyAlgorithms.A128GCMKW) &&
                contains(KeyAlgorithms.A192GCMKW) &&
                contains(KeyAlgorithms.A256GCMKW)
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
