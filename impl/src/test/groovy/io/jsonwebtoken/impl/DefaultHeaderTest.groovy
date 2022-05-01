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
import org.junit.Before
import org.junit.Test

import static org.junit.Assert.assertEquals

class DefaultHeaderTest {
    
    private DefaultHeader header
    
    @Before
    void setUp() {
        header = new DefaultHeader()
    }

    @Test
    void testType() {
        header.setType('foo')
        assertEquals header.getType(), 'foo'
    }

    @Test
    void testContentType() {
        header.setContentType('bar')
        assertEquals header.getContentType(), 'bar'
    }

    @Test
    void testSetCompressionAlgorithm() {
        header.setCompressionAlgorithm("DEF")
        assertEquals "DEF", header.getCompressionAlgorithm()
    }

    @SuppressWarnings('GrDeprecatedAPIUsage')
    @Test
    void testBackwardsCompatibleCompressionHeader() {
        header.put(Header.DEPRECATED_COMPRESSION_ALGORITHM, "DEF")
        assertEquals "DEF", header.getCompressionAlgorithm()
    }

    @Test
    void testGetName() {
        def header = new DefaultHeader()
        assertEquals 'JWT header', header.getName()
    }
}
