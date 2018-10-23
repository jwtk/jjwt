package io.jsonwebtoken.io

import org.junit.Test

import static org.junit.Assert.*

class EncodersTest {

    @Test
    void testBase64() {
        new Encoders() //not allowed in java, including here only to pass test coverage assertions
        assertTrue Encoders.BASE64 instanceof ExceptionPropagatingEncoder
        assertTrue Encoders.BASE64.encoder instanceof Base64Encoder
    }

    @Test
    void testBase64Url() {
        assertTrue Encoders.BASE64URL instanceof ExceptionPropagatingEncoder
        assertTrue Encoders.BASE64URL.encoder instanceof Base64UrlEncoder
    }
}
