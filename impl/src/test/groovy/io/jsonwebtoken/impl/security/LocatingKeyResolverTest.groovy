/*
 * Copyright (C) 2022 jsonwebtoken.io
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

import io.jsonwebtoken.impl.DefaultClaims
import io.jsonwebtoken.impl.DefaultJwsHeader
import org.junit.Test

import java.nio.charset.StandardCharsets

import static org.junit.Assert.assertSame

class LocatingKeyResolverTest {

    @Test(expected = IllegalArgumentException)
    void testNullConstructor() {
        new LocatingKeyResolver(null)
    }

    @Test
    void testResolveSigningKeyClaims() {
        def key = TestKeys.HS256
        def locator = new ConstantKeyLocator(key, null)
        def header = new DefaultJwsHeader([:])
        def claims = new DefaultClaims()
        assertSame key, new LocatingKeyResolver(locator).resolveSigningKey(header, claims)
    }

    @Test
    void testResolveSigningKeyPayload() {
        def key = TestKeys.HS256
        def locator = new ConstantKeyLocator(key, null)
        def header = new DefaultJwsHeader([:])
        def payload = 'hello world'.getBytes(StandardCharsets.UTF_8)
        assertSame key, new LocatingKeyResolver(locator).resolveSigningKey(header, payload)
    }
}
