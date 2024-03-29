/*
 * Copyright (C) 2021 jsonwebtoken.io
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
package io.jsonwebtoken.impl.io

import io.jsonwebtoken.io.DecodingException
import org.junit.Test

import static org.junit.Assert.*

class CodecTest {

    @Test
    void testDecodingExceptionThrowsIAE() {
        CharSequence s = 't#t'
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
