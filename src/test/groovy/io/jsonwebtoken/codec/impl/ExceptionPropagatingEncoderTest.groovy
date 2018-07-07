package io.jsonwebtoken.codec.impl

import io.jsonwebtoken.codec.Encoder
import io.jsonwebtoken.codec.EncodingException
import org.junit.Test

import static org.junit.Assert.*

class ExceptionPropagatingEncoderTest {


    @Test(expected = IllegalArgumentException)
    void testWithNullConstructorArgument() {
        new ExceptionPropagatingEncoder(null)
    }

    @Test(expected = IllegalArgumentException)
    void testEncodeWithNullArgument() {
        def encoder = new ExceptionPropagatingEncoder<>(new Base64UrlEncoder())
        encoder.encode(null)
    }

    @Test
    void testEncodePropagatesEncodingException() {
        def encoder = new ExceptionPropagatingEncoder(new Encoder() {
            @Override
            Object encode(Object o) throws EncodingException {
                throw new EncodingException("problem", new IOException("dummy"))
            }
        })
        try {
            encoder.encode("hello")
            fail()
        } catch (EncodingException ex) {
            assertEquals "problem", ex.getMessage()
        }
    }

    @Test
    void testEncodeWithNonEncodingExceptionIsWrappedAsEncodingException() {

        def causeEx = new RuntimeException("whatevs")

        def encoder = new ExceptionPropagatingEncoder(new Encoder() {
            @Override
            Object encode(Object o) throws EncodingException {
                throw causeEx;
            }
        })
        try {
            encoder.encode("hello")
            fail()
        } catch (EncodingException ex) {
            assertEquals "Unable to encode input: whatevs", ex.getMessage()
            assertSame causeEx, ex.getCause()
        }
    }
}
