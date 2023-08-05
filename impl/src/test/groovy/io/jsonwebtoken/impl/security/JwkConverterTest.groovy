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

import io.jsonwebtoken.security.*
import org.junit.Test

import static org.junit.Assert.assertEquals
import static org.junit.Assert.fail

class JwkConverterTest {

    static String typeString(def target) {
        return JwkConverter.typeString(target)
    }

    @Test
    void testJwkClassTypeString() {
        assertEquals 'JWK', typeString(Jwk.class)
    }

    @Test
    void testSecretJwkClassTypeString() {
        assertEquals 'Secret JWK', typeString(SecretJwk.class)
    }

    @Test
    void testSecretJwkTypeString() {
        def jwk = Jwks.builder().key(TestKeys.HS256).build()
        assertEquals 'Secret JWK', typeString(jwk)
    }

    @Test
    void testPublicJwkClassTypeString() {
        assertEquals 'Public JWK', typeString(PublicJwk.class)
    }

    @Test
    void testEcPublicJwkClassTypeString() {
        assertEquals 'EC Public JWK', typeString(EcPublicJwk.class)
    }

    @Test
    void testEdPublicJwkClassTypeString() {
        assertEquals 'Edwards Curve Public JWK', typeString(OctetPublicJwk.class)
    }

    @Test
    void testRsaPublicJwkClassTypeString() {
        assertEquals 'RSA Public JWK', typeString(RsaPublicJwk.class)
    }

    @Test
    void testPrivateJwkClassTypeString() {
        assertEquals 'Private JWK', typeString(PrivateJwk.class)
    }

    @Test
    void testEcPrivateJwkClassTypeString() {
        assertEquals 'EC Private JWK', typeString(EcPrivateJwk.class)
    }

    @Test
    void testEdPrivateJwkClassTypeString() {
        assertEquals 'Edwards Curve Private JWK', typeString(OctetPrivateJwk.class)
    }

    @Test
    void testRsaPrivateJwkClassTypeString() {
        assertEquals 'RSA Private JWK', typeString(RsaPrivateJwk.class)
    }

    @Test
    void testPrivateJwk() {
        JwkConverter<PrivateJwk> converter = new JwkConverter<>(PrivateJwk.class)
        def jwk = Jwks.builder().key(TestKeys.HS256).build()
        try {
            converter.applyFrom(jwk)
            fail()
        } catch (IllegalArgumentException expected) {
            String msg = "Value must be a Private JWK, not a Secret JWK."
            assertEquals msg, expected.getMessage()
        }
    }

    @Test
    void testRsaPrivateJwk() {
        JwkConverter<RsaPublicJwk> converter = new JwkConverter<>(RsaPublicJwk.class)
        def jwk = Jwks.builder().key(TestKeys.HS256).build()
        try {
            converter.applyFrom(jwk)
            fail()
        } catch (IllegalArgumentException expected) {
            String msg = "Value must be an RSA Public JWK, not a Secret JWK."
            assertEquals msg, expected.getMessage()
        }
    }
}
