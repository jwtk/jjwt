package io.jsonwebtoken.impl.security

import io.jsonwebtoken.security.Algorithms
import org.junit.Test

import static org.junit.Assert.assertEquals

class AlgorithmsTest {

    @Test
    void testCtor() {
        try {
            new Algorithms()
        } catch (AssertionError error) {
            String msg = 'io.jsonwebtoken.security.Algorithms may not be instantiated.'
            assertEquals(msg, error.getMessage())
        }
    }
}
