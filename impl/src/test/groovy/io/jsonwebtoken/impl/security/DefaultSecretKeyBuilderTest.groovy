package io.jsonwebtoken.impl.security

import org.junit.Test

import static org.junit.Assert.*

class DefaultSecretKeyBuilderTest {

    @Test
    void testInvalidBitLength() {
        try {
            //noinspection GroovyResultOfObjectAllocationIgnored
            new DefaultSecretKeyBuilder("AES", 127)
            fail()
        } catch (IllegalArgumentException expected) {
            String msg = "bitLength must be an even multiple of 8"
            assertEquals msg, expected.getMessage()
        }
    }
}
