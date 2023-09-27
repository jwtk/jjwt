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

import io.jsonwebtoken.lang.Strings
import org.junit.Test

import static org.junit.Assert.assertEquals

class Base64DecoderTest {

    @Test(expected = IllegalArgumentException)
    void testDecodeWithNullArgument() {
        new Base64Decoder().decode(null)
    }

    @Test
    void decode() {
        String encoded = 'SGVsbG8g5LiW55WM' // Hello 世界
        byte[] bytes = new Base64Decoder().decode(encoded)
        String result = new String(bytes, Strings.UTF_8)
        assertEquals 'Hello 世界', result
    }
}
