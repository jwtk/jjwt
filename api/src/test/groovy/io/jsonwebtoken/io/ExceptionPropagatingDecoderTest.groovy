/*
 * Copyright (C) 2014 jsonwebtoken.io
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.jsonwebtoken.io


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
                throw new DecodingException("problem", new java.io.IOException("dummy"))
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
