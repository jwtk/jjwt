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

import io.jsonwebtoken.security.Keys
import io.jsonwebtoken.security.Password
import io.jsonwebtoken.security.SecretKeyBuilder
import org.junit.Test

import static org.junit.Assert.assertSame

class ProvidedSecretKeyBuilderTest {

    @SuppressWarnings('GrDeprecatedAPIUsage')
    @Test
    void testBuildSecretKeyWithoutProvider() {
        // does not wrap in ProviderKey:
        assertSame TestKeys.HS256, SecretKeyBuilder.with(TestKeys.HS256).build()
        assertSame TestKeys.HS256, Keys.builder(TestKeys.HS256).build() // for coverage, will be removed before 1.0
    }

    @Test
    void testBuildPasswordWithoutProvider() {
        def password = Password.of('foo'.toCharArray())
        assertSame password, SecretKeyBuilder.with(password).build() // does not wrap in ProviderKey
    }

    @Test
    void testBuildPasswordWithProvider() {
        def password = Password.of('foo'.toCharArray())
        // does not wrap in ProviderKey:
        assertSame password, SecretKeyBuilder.with(password).provider(new TestProvider()).build()
    }
}
