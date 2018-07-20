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
package io.jsonwebtoken.impl

import io.jsonwebtoken.lang.Strings
import org.junit.Test

import static org.junit.Assert.*

@Deprecated //remove just before 1.0.0 release
class AndroidBase64CodecTest {

    @Test
    void testEncode() {
        String input = 'Hello 世界'
        byte[] bytes = input.getBytes(Strings.UTF_8)
        String encoded = new AndroidBase64Codec().encode(bytes)
        assertEquals 'SGVsbG8g5LiW55WM', encoded
    }

    @Test
    void testDecode() {
        String encoded = 'SGVsbG8g5LiW55WM' // Hello 世界
        byte[] bytes = new AndroidBase64Codec().decode(encoded)
        String result = new String(bytes, Strings.UTF_8)
        assertEquals 'Hello 世界', result
    }
}
