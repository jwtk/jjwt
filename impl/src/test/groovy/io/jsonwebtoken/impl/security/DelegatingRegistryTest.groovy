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
package io.jsonwebtoken.impl.security

import io.jsonwebtoken.impl.lang.DefaultRegistry
import io.jsonwebtoken.impl.lang.Functions
import io.jsonwebtoken.lang.Registry
import org.junit.Test

import static org.junit.Assert.assertEquals

class DelegatingRegistryTest {

    @Test
    void testSize() {
        def values = ['foo', 'bar', 'baz']
        Registry<String, String> reg = new TestDelegatingRegistry(values)
        assertEquals values.size(), reg.size()
    }

    final class TestDelegatingRegistry extends DelegatingRegistry<String> {
        TestDelegatingRegistry(Collection<String> values) {
            super(new DefaultRegistry<String, String>('test', 'id', values, Functions.identity()))
        }
    }
}
