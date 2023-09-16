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

import io.jsonwebtoken.impl.lang.Bytes
import io.jsonwebtoken.impl.lang.Parameter
import io.jsonwebtoken.impl.lang.Parameters
import io.jsonwebtoken.io.Encoders
import org.junit.Test

import static org.junit.Assert.*

class DefaultJwkContextTest {

    @Test
    void testX509Url() {
        def uri = URI.create('https://github.com/jwtk/jjwt')
        def ctx = new DefaultJwkContext()
        ctx.x509Url(uri)
        assertEquals uri, ctx.getX509Url()
        assertEquals uri.toString(), ctx.get('x5u')
    }

    @Test
    void testX509CertificateChain() {
        def chain = TestKeys.RS256.chain
        def ctx = new DefaultJwkContext()
        ctx.x509CertificateChain(chain)
        assertEquals chain, ctx.getX509CertificateChain()
    }

    @Test
    void testX509CertificateSha1Thumbprint() {
        def thumbprint = Bytes.randomBits(128)
        def ctx = new DefaultJwkContext()
        ctx.x509CertificateSha1Thumbprint(thumbprint)
        assertArrayEquals thumbprint, ctx.getX509CertificateSha1Thumbprint()
        assertEquals Encoders.BASE64URL.encode(thumbprint), ctx.get('x5t')
    }

    @Test
    void testX509CertificateSha256Thumbprint() {
        def thumbprint = Bytes.randomBits(256)
        def ctx = new DefaultJwkContext()
        ctx.x509CertificateSha256Thumbprint(thumbprint)
        assertArrayEquals thumbprint, ctx.getX509CertificateSha256Thumbprint()
        assertEquals Encoders.BASE64URL.encode(thumbprint), ctx.get('x5t#S256')
    }

    @Test
    void testGetName() {
        def ctx = new DefaultJwkContext()
        assertEquals 'JWK', ctx.getName()
    }

    @Test
    void testGetNameWhenSecretJwk() {
        def ctx = new DefaultJwkContext(DefaultSecretJwk.PARAMS)
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
        def ctx = new DefaultJwkContext(DefaultSecretJwk.PARAMS)
        ctx.put('kty', 'oct')
        ctx.put('k', 'test')
        String s = '[kty:oct, k:<redacted>]'
        assertEquals "$s", "$ctx"
    }

    @Test
    void testGStringToStringPrintsRedactedValues() {
        def ctx = new DefaultJwkContext(DefaultSecretJwk.PARAMS)
        ctx.put('kty', 'oct')
        ctx.put('k', 'test')
        String s = '{kty=oct, k=<redacted>}'
        assertEquals "$s", "${ctx.toString()}"
    }

    @Test
    void testFieldWithoutKey() {
        def ctx = new DefaultJwkContext(DefaultSecretJwk.PARAMS)
        Parameter param = Parameters.string('kid', 'My Key ID')
        def newCtx = ctx.parameter(param)
        assertSame param, newCtx.@PARAMS.get('kid')
        assertNull newCtx.getKey()
    }

    @Test
    void testFieldWithKey() {
        def key = TestKeys.HS256
        def ctx = new DefaultJwkContext(DefaultSecretJwk.PARAMS)
        ctx.setKey(key)
        Parameter param = Parameters.string('kid', 'My Key ID')
        def newCtx = ctx.parameter(param)
        assertSame param, newCtx.@PARAMS.get('kid') // registry created with custom param instead of default
        assertSame key, newCtx.getKey() // copied over correctly
    }
}
