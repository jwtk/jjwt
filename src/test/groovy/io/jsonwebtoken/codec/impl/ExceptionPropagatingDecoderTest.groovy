package io.jsonwebtoken.codec.impl

import io.jsonwebtoken.codec.Decoder
import io.jsonwebtoken.codec.DecodingException
import io.jsonwebtoken.codec.EncodingException
import org.junit.Test

import static org.junit.Assert.*

class ExceptionPropagatingDecoderTest {

    @Test(expected = IllegalArgumentException)
    void testWithNullConstructorArgument() {
        new ExceptionPropagatingDecoder(null)
    }

    @Test(expected = IllegalArgumentException)
    void testEncodeWithNullArgument() {
        def decoder = new ExceptionPropagatingDecoder<>(new Base64UrlDecoder())
        decoder.decode(null)
    }

    @Test
    void testEncodePropagatesDecodingException() {
        def decoder = new ExceptionPropagatingDecoder(new Decoder() {
            @Override
            Object decode(Object o) throws DecodingException {
                throw new DecodingException("problem", new IOException("dummy"))
            }
        })
        try {
            decoder.decode("hello")
            fail()
        } catch (DecodingException ex) {
            assertEquals "problem", ex.getMessage()
        }
    }

    @Test
    void testEncodeWithNonEncodingExceptionIsWrappedAsEncodingException() {

        def causeEx = new RuntimeException("whatevs")

        def decoder = new ExceptionPropagatingDecoder(new Decoder() {
            @Override
            Object decode(Object o) throws EncodingException {
                throw causeEx
            }
        })
        try {
            decoder.decode("hello")
            fail()
        } catch (DecodingException ex) {
            assertEquals "Unable to decode input: whatevs", ex.getMessage()
            assertSame causeEx, ex.getCause()
        }
    }
}
