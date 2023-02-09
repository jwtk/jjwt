package io.jsonwebtoken.impl.security

import io.jsonwebtoken.security.Algorithms
import io.jsonwebtoken.security.HashAlgorithm
import org.junit.Test

import static org.junit.Assert.*

class HashAlgorithmsTest {

    static boolean contains(HashAlgorithm alg) {
        return Algorithms.hash.values().contains(alg)
    }

    @Test
    void testValues() {
        assertEquals 1, Algorithms.hash.values().size()
        assertTrue(contains(Algorithms.hash.SHA256)) // add more later
    }

    @Test
    void testForId() {
        for (HashAlgorithm alg : Algorithms.hash.values()) {
            assertSame alg, Algorithms.hash.get(alg.getId())
        }
    }

    @Test
    void testForIdCaseInsensitive() {
        for (HashAlgorithm alg : Algorithms.hash.values()) {
            assertSame alg, Algorithms.hash.get(alg.getId().toLowerCase())
        }
    }

    @Test(expected = IllegalArgumentException)
    void testForIdWithInvalidId() {
        //unlike the 'find' paradigm, 'get' requires the value to exist
        Algorithms.hash.get('invalid')
    }

    @Test
    void testFindById() {
        for (HashAlgorithm alg : Algorithms.hash.values()) {
            assertSame alg, Algorithms.hash.find(alg.getId())
        }
    }

    @Test
    void testFindByIdCaseInsensitive() {
        for (HashAlgorithm alg : Algorithms.hash.values()) {
            assertSame alg, Algorithms.hash.find(alg.getId().toLowerCase())
        }
    }

    @Test
    void testFindByIdWithInvalidId() {
        // 'find' paradigm can return null if not found
        assertNull Algorithms.hash.find('invalid')
    }
}
