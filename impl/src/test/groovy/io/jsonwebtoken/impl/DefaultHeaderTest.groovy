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


import org.junit.Test

import static org.junit.Assert.assertEquals
import static org.junit.Assert.assertNull

class DefaultHeaderTest {
    
    private DefaultHeader header

    private static DefaultHeader h(Map<String, ?> m) {
        return new DefaultHeader(m)
    }
    
    @Test
    void testType() {
        header = h([typ: 'foo'])
        assertEquals 'foo', header.getType()
        assertEquals 'foo', header.get('typ')
    }

    @Test
    void testContentType() {
        header = h([cty: 'bar'])
        // Per per https://www.rfc-editor.org/rfc/rfc7515.html#section-4.1.10, the raw header should have a
        // compact form, but application developers shouldn't have to check for that all the time, so our getter has
        // the normalized form:
        assertEquals 'bar', header.get('cty') // raw compact form
        assertEquals 'application/bar', header.getContentType() // getter normalized form
    }

    @Test
    void testAlgorithm() {
        header = h([alg: 'foo'])
        assertEquals 'foo', header.getAlgorithm()
        assertEquals 'foo', header.get('alg')
    }

    @Test
    void testSetCompressionAlgorithm() {
        header = h([zip: 'DEF'])
        assertEquals "DEF", header.getCompressionAlgorithm()
        assertEquals 'DEF', header.get('zip')
    }

    @SuppressWarnings('GrDeprecatedAPIUsage')
    @Test
    void testBackwardsCompatibleCompressionHeader() {
        header = h([calg: 'DEF'])
        assertEquals "DEF", header.getCompressionAlgorithm()
        assertEquals 'DEF', header.get('calg')
        assertNull header.get('zip')
    }

    @Test
    void testGetName() {
        def header = new DefaultHeader([:])
        assertEquals 'JWT header', header.getName()
    }
}
