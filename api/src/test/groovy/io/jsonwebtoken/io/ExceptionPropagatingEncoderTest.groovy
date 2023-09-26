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
                throw new EncodingException("problem", new java.io.IOException("dummy"))
            }

            @Override
            OutputStream encode(OutputStream out) {
                return null
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

            @Override
            OutputStream encode(OutputStream out) {
                return null
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
