/*
 * Copyright © 2021 jsonwebtoken.io
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
package io.jsonwebtoken.security

import org.junit.Test

import static org.junit.Assert.assertEquals

class InvalidKeyExceptionTest {

    @Test
    void testDefaultConstructor() {
        def msg = "my message"
        def exception = new InvalidKeyException(msg)
        assertEquals msg, exception.getMessage()
    }

    @Test
    void testConstructorWithCause() {
        def rootMsg = 'root error'
        def msg = 'wrapping'
        def ioException = new IOException(rootMsg)
        def exception = new InvalidKeyException(msg, ioException)
        assertEquals msg, exception.getMessage()
        assertEquals ioException, exception.getCause()
    }
}
