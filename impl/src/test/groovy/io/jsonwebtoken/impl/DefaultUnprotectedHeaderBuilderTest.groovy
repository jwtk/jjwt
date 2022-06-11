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
package io.jsonwebtoken.impl

import org.junit.Before
import org.junit.Test

import static org.junit.Assert.assertEquals
import static org.junit.Assert.assertTrue

class DefaultUnprotectedHeaderBuilderTest {

    static DefaultUnprotectedHeaderBuilder builder

    @Before
    void setUp() {
        builder = new DefaultUnprotectedHeaderBuilder()
    }

    @Test
    void testNewHeader() {
        assertTrue builder.header instanceof DefaultUnprotectedHeader
    }

    @Test
    void testType() {
        String type = 'foo'
        assertEquals type, builder.setType(type).build().getType()
    }

    @Test
    void testContentType() {
        String cty = 'text/plain'
        assertEquals cty, builder.setContentType(cty).build().getContentType()
    }

    @Test
    void testAlgorithm() {
        String alg = 'none'
        assertEquals alg, builder.setAlgorithm(alg).build().getAlgorithm()
    }

    @Test
    void testCompressionAlgorithm() {
        String zip = 'DEF'
        assertEquals zip, builder.setCompressionAlgorithm(zip).build().getCompressionAlgorithm()
    }

    @Test
    void testPut() {
        assertEquals 'bar', builder.put('foo', 'bar').build().get('foo')
    }

    @Test
    void testPutAll() {
        def m = ['foo': 'bar', 'baz': 'bat']
        assertEquals m, builder.putAll(m).build()
    }

    @Test
    void testRemove() {
        def header = builder.put('foo', 'bar').remove('foo').build()
        assertTrue header.isEmpty()
    }

    @Test
    void testClear() {
        def m = ['foo': 'bar', 'baz': 'bat']
        def header = builder.putAll(m).clear().build()
        assertTrue header.isEmpty()
    }
}
