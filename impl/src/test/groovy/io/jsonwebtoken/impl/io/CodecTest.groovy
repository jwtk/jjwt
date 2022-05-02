package io.jsonwebtoken.impl.io

import io.jsonwebtoken.io.DecodingException
import org.junit.Test

import static org.junit.Assert.*

class CodecTest {

    @Test
    void testDecodingExceptionThrowsIAE() {
        String s = 't#t'
        try {
            Codec.BASE64URL.applyFrom(s)
            fail()
        } catch (IllegalArgumentException expected) {
            def cause = expected.getCause()
            assertTrue cause instanceof DecodingException
            String msg = "Cannot decode input String. Cause: ${cause.getMessage()}"
            assertEquals msg, expected.getMessage()
        }
    }
}
