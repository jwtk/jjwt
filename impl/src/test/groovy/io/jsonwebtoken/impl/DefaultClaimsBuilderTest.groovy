/*
 * Copyright (C) 2023 jsonwebtoken.io
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

class DefaultClaimsBuilderTest {

    DefaultClaimsBuilder builder

    @Before
    void setUp() {
        this.builder = new DefaultClaimsBuilder()
    }

    @Test
    void testPut() {
        builder.put('foo', 'bar')
        assertEquals 'bar', builder.build().foo
    }

    @Test
    void testPutAll() {
        def m = [foo: 'bar', hello: 'world']
        builder.putAll(m)
        assertEquals m, builder.build()
    }

    @Test
    void testPutAllEmpty() {
        builder.putAll([:])
        assertTrue builder.build().isEmpty()
    }

    @Test
    void testPutAllNull() {
        builder.putAll((Map<String,Object>)null)
        assertTrue builder.build().isEmpty()
    }

    @Test
    void testRemove() {
        builder.put('foo', 'bar')
        assertEquals 'bar', builder.build().foo
        builder.remove('foo')
        assertTrue builder.build().isEmpty()
    }

    @Test
    void testClear() {
        def m = [foo: 'bar', hello: 'world']
        builder.putAll(m)
        assertEquals m, builder.build()

        builder.clear()
        assertTrue builder.build().isEmpty()
    }
}
