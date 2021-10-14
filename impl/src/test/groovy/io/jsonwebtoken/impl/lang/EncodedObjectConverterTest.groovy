package io.jsonwebtoken.impl.lang

import io.jsonwebtoken.impl.security.DefaultJwkContext
import org.junit.Test

import static org.junit.Assert.*

class EncodedObjectConverterTest {

    @Test
    void testApplyFromWithInvalidType() {
        def converter = DefaultJwkContext.URI_CONVERTER
        assertTrue converter instanceof EncodedObjectConverter
        int value = 42
        try {
            converter.applyFrom(value)
            fail("IllegalArgumentException should have been thrown.")
        } catch (IllegalArgumentException expected) {
            String msg = "Values must be either String or java.net.URI instances. Value type found: java.lang.Integer. Value: ${value}"
            assertEquals msg, expected.getMessage()
        }
    }
}
