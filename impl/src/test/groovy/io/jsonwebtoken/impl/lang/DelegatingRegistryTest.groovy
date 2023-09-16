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
package io.jsonwebtoken.impl.lang


import io.jsonwebtoken.lang.Registry
import org.junit.Before
import org.junit.Test

import static org.junit.Assert.assertEquals

class DelegatingRegistryTest {

    Registry<String, String> registry

    @Before
    void setUp() {
        def src = new DefaultRegistry('test', 'id', ['a', 'b', 'c'], Functions.identity())
        this.registry = new DelegatingRegistry(src)
    }

    @Test
    void testForKey() {
        assertEquals 'a', registry.forKey('a')
        assertEquals 'b', registry.forKey('b')
        assertEquals 'c', registry.forKey('c')

    }

    @Test(expected = IllegalArgumentException)
    void testForKeyInvalid() {
        registry.forKey('invalid') // any key value that doesn't exist
    }
}
