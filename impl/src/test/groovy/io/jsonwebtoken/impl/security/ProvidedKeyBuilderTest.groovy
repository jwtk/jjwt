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
import io.jsonwebtoken.security.Keys
import io.jsonwebtoken.security.SecretKeyBuilder
import org.junit.Test

import javax.crypto.SecretKey
import javax.crypto.spec.SecretKeySpec
import java.security.PrivateKey
import java.security.Provider

import static org.junit.Assert.assertSame
import static org.junit.Assert.assertTrue

class ProvidedKeyBuilderTest {

    @Test
    void testBuildPrivateKeyWithProvider() {
        Provider provider = new TestProvider()
        PrivateKey privateKey = TestKeys.ES256.pair.private
        def result = Keys.builder(privateKey).provider(provider).build()

        assertTrue result instanceof ProviderPrivateKey
        assertSame provider, (result as ProviderPrivateKey).getProvider()
        assertSame privateKey, (result as ProviderPrivateKey).getKey()
    }

    @Test
    void testBuildWithSpecifiedProviderKey() {
        Provider provider = new TestProvider()
        SecretKey key = new SecretKeySpec(Bytes.random(256), 'AES')
        def providerKey = SecretKeyBuilder.with(key).provider(provider).build() as ProviderSecretKey

        assertSame provider, providerKey.getProvider()
        assertSame key, providerKey.getKey()

        // now for the test: ensure that our provider key isn't wrapped again
        SecretKey returned = SecretKeyBuilder.with(providerKey).provider(new TestProvider('different')).build()

        assertSame providerKey, returned // not wrapped again
    }
}
