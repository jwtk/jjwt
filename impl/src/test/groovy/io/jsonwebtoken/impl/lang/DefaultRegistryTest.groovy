/*
 * Copyright © 2023 jsonwebtoken.io
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

import org.junit.Before
import org.junit.Test

import static org.junit.Assert.assertEquals
import static org.junit.Assert.fail

class DefaultRegistryTest {

    DefaultRegistry<String, String> reg

    @Before
    void setUp() {
        reg = new DefaultRegistry<>('test', 'id', ['a', 'b', 'c', 'd'], Functions.identity())
    }

    static void immutable(Closure c) {
        try {
            c.call()
            fail()
        } catch (UnsupportedOperationException expected) {
            String msg = 'Registries are immutable and cannot be modified.'
            assertEquals msg, expected.getMessage()
        }
    }

    @Test
    void testImmutable() {
        immutable { reg.put('foo', 'bar') }
        immutable { reg.putAll([foo: 'bar']) }
        immutable { reg.remove('kty') }
        immutable { reg.clear() }
    }

    @Test
    void testApplySameAsGet() {
        def key = 'a'
        assertEquals reg.apply(key), reg.get(key)
    }
}
