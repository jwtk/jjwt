/*
 * Copyright (C) 2014 jsonwebtoken.io
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
package io.jsonwebtoken

import org.junit.Test

import javax.crypto.spec.SecretKeySpec
import java.nio.charset.StandardCharsets

import static org.easymock.EasyMock.*
import static org.junit.Assert.*

class SigningKeyResolverAdapterTest {

    @Test(expected=UnsupportedJwtException) //should throw since called but not overridden
    void testDefaultResolveSigningKeyBytesFromClaims() {
        def header = createMock(JwsHeader)
        def claims = createMock(Claims)
        new SigningKeyResolverAdapter().resolveSigningKeyBytes(header, claims)
    }

    @Test(expected=UnsupportedJwtException) //should throw since called but not overridden
    void testDefaultResolveSigningKeyBytesFromStringPayload() {
        def header = createMock(JwsHeader)
        new SigningKeyResolverAdapter().resolveSigningKeyBytes(header, "hi".getBytes(StandardCharsets.UTF_8))
    }

    @Test
    void testResolveSigningKeyHmac() {

        JwsHeader header = createMock(JwsHeader)
        Claims claims = createMock(Claims)

        byte[] bytes = new byte[32]
        new Random().nextBytes(bytes)

        expect(header.getAlgorithm()).andReturn("HS256")

        replay header, claims

        def adapter = new SigningKeyResolverAdapter() {
            @Override
            byte[] resolveSigningKeyBytes(JwsHeader h, Claims c) {
                assertSame header, h
                assertSame claims, c
                return bytes
            }
        }

        def key = adapter.resolveSigningKey(header, claims)

        verify header, claims

        assertTrue key instanceof SecretKeySpec
        assertEquals 'HmacSHA256', key.algorithm
        assertTrue Arrays.equals(bytes, key.encoded)
    }

    @Test(expected=IllegalArgumentException)
    void testResolveSigningKeyDefaultWithoutHmac() {
        JwsHeader header = createMock(JwsHeader)
        Claims claims = createMock(Claims)
        expect(header.getAlgorithm()).andReturn("RS256")
        replay header, claims
        new SigningKeyResolverAdapter().resolveSigningKey(header, claims)
    }

    @Test
    void testResolveSigningKeyPayloadHmac() {

        JwsHeader header = createMock(JwsHeader)

        byte[] keyBytes = new byte[32]
        new Random().nextBytes(keyBytes)
        byte[] payloadBytes = 'hi'.getBytes(StandardCharsets.UTF_8)

        expect(header.getAlgorithm()).andReturn("HS256")

        replay header

        def adapter = new SigningKeyResolverAdapter() {
            @Override
            byte[] resolveSigningKeyBytes(JwsHeader h, byte[] payload) {
                assertSame header, h
                assertArrayEquals payloadBytes, payload
                return keyBytes
            }
        }

        def key = adapter.resolveSigningKey(header, payloadBytes)

        verify header

        assertTrue key instanceof SecretKeySpec
        assertEquals 'HmacSHA256', key.algorithm
        assertTrue Arrays.equals(keyBytes, key.encoded)
    }

    @Test(expected=IllegalArgumentException)
    void testResolveSigningKeyPayloadWithoutHmac() {
        JwsHeader header = createMock(JwsHeader)
        expect(header.getAlgorithm()).andReturn("RS256")
        replay header
        new SigningKeyResolverAdapter().resolveSigningKey(header, 'hi'.getBytes(StandardCharsets.UTF_8))
    }
}
