/*
 * Copyright (C) 2015 jsonwebtoken.io
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
package io.jsonwebtoken

import org.junit.Test

import static org.junit.Assert.assertEquals

class CompressionExceptionTest  {

    @Test
    void testDefaultConstructor() {
        def exception = new CompressionException("my message")

        assertEquals "my message", exception.getMessage()
    }

    @Test
    void testConstructorWithCause() {

        def ioException = new IOException("root error")

        def exception = new CompressionException("wrapping", ioException)

        assertEquals "wrapping", exception.getMessage()
        assertEquals ioException, exception.getCause()
    }
}