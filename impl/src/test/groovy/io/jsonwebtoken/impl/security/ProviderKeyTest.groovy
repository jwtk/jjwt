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
package io.jsonwebtoken.impl.security

import io.jsonwebtoken.impl.lang.Bytes
import org.junit.Test

import java.security.Provider

import static org.junit.Assert.assertEquals
import static org.junit.Assert.assertSame

class ProviderKeyTest {

    static final Provider PROVIDER = new TestProvider()

    @Test(expected = IllegalArgumentException)
    void testConstructorWithNullProvider() {
        new ProviderKey<>(null, TestKeys.HS256)
    }

    @Test(expected = IllegalArgumentException)
    void testConstructorWithNullKey() {
        new ProviderKey<>(PROVIDER, null)
    }

    @Test
    void testConstructorWithProviderKey() {
        def key = new ProviderKey(PROVIDER, TestKeys.HS256)
        // wrapping throws an exception:
        try {
            new ProviderKey<>(PROVIDER, key)
        } catch (IllegalArgumentException iae) {
            String msg = 'Nesting not permitted.'
            assertEquals msg, iae.getMessage()
        }
    }

    @Test
    void testGetKey() {
        def src = new TestKey()
        def key = new ProviderKey(PROVIDER, src)
        assertSame src, key.getKey()
    }

    @Test
    void testGetProvider() {
        def src = new TestKey()
        def key = new ProviderKey(PROVIDER, src)
        assertSame PROVIDER, key.getProvider()
    }

    @Test
    void testGetAlgorithm() {
        String name = 'myAlg'
        def key = new ProviderKey(PROVIDER, new TestKey(algorithm: name))
        assertEquals name, key.getAlgorithm()
    }

    @Test
    void testGetFormat() {
        String name = 'myFormat'
        def key = new ProviderKey(PROVIDER, new TestKey(format: name))
        assertEquals name, key.getFormat()
    }

    @Test
    void testGetEncoded() {
        byte[] encoded = Bytes.random(256)
        def key = new ProviderKey(PROVIDER, new TestKey(encoded: encoded))
        assertSame encoded, key.getEncoded()
    }
}
