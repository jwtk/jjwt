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

import io.jsonwebtoken.Header
import org.junit.Test
import static org.junit.Assert.*

class DefaultHeaderTest {

    @Test
    void testType() {

        def h = new DefaultHeader()

        h.setType('foo')
        assertEquals h.getType(), 'foo'
    }

    @Test
    void testContentType() {

        def h = new DefaultHeader()

        h.setContentType('bar')
        assertEquals h.getContentType(), 'bar'
    }

    @Test
    void testSetCompressionAlgorithm() {
        def h = new DefaultHeader()
        h.setCompressionAlgorithm("DEF")
        assertEquals "DEF", h.getCompressionAlgorithm()
    }

    @Test
    void testBackwardsCompatibleCompressionHeader() {
        def h = new DefaultHeader()
        h.put(Header.DEPRECATED_COMPRESSION_ALGORITHM, "DEF")
        assertEquals "DEF", h.getCompressionAlgorithm()
    }
}
