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

import org.junit.Test

import static org.junit.Assert.assertEquals

class DefaultJwkContextTest {

    @Test
    void testGetName() {
        def ctx = new DefaultJwkContext()
        assertEquals 'JWK', ctx.getName()
    }

    @Test
    void testGetNameWhenSecretJwk() {
        def ctx = new DefaultJwkContext(DefaultSecretJwk.FIELDS)
        ctx.put('kty', 'oct')
        assertEquals 'Secret JWK', ctx.getName()
    }

    @Test
    void testGetNameWithGenericPublicKey() {
        def ctx = new DefaultJwkContext()
        ctx.setKey(TestKeys.ES256.pair.public)
        assertEquals 'Public JWK', ctx.getName()
    }

    @Test
    void testGetNameWithGenericPrivateKey() {
        def ctx = new DefaultJwkContext()
        ctx.setKey(TestKeys.ES256.pair.private)
        assertEquals 'Private JWK', ctx.getName()
    }

    @Test
    void testGetNameWithEdwardsPublicKey() {
        def ctx = new DefaultJwkContext()
        ctx.setKey(TestKeys.X448.pair.public)
        ctx.setType(DefaultOctetPublicJwk.TYPE_VALUE)
        assertEquals 'Octet Public JWK', ctx.getName()
    }

    @Test
    void testGetNameWithEdwardsPrivateKey() {
        def ctx = new DefaultJwkContext()
        ctx.setKey(TestKeys.X448.pair.private)
        ctx.setType(DefaultOctetPublicJwk.TYPE_VALUE)
        assertEquals 'Octet Private JWK', ctx.getName()
    }

    @Test
    void testGStringPrintsRedactedValues() {
        // DO NOT REMOVE THIS METHOD: IT IS CRITICAL TO ENSURE GROOVY STRINGS DO NOT LEAK SECRET/PRIVATE KEY MATERIAL
        def ctx = new DefaultJwkContext(DefaultSecretJwk.FIELDS)
        ctx.put('kty', 'oct')
        ctx.put('k', 'test')
        String s = '[kty:oct, k:<redacted>]'
        assertEquals "$s", "$ctx"
    }

    @Test
    void testGStringToStringPrintsRedactedValues() {
        def ctx = new DefaultJwkContext(DefaultSecretJwk.FIELDS)
        ctx.put('kty', 'oct')
        ctx.put('k', 'test')
        String s = '{kty=oct, k=<redacted>}'
        assertEquals "$s", "${ctx.toString()}"
    }
}
