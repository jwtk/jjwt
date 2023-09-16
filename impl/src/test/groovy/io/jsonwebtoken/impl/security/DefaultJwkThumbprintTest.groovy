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

import io.jsonwebtoken.io.Encoders
import io.jsonwebtoken.security.HashAlgorithm
import io.jsonwebtoken.security.Jwks
import org.junit.Before
import org.junit.Test

import java.nio.charset.StandardCharsets
import java.security.MessageDigest

import static org.junit.Assert.*

class DefaultJwkThumbprintTest {

    private static String content = "Hello World"
    private static HashAlgorithm alg = Jwks.HASH.SHA256
    private static byte[] digest = alg.digest(new DefaultRequest<byte[]>(content.getBytes(StandardCharsets.UTF_8), null, null))
    private static String expectedToString = Encoders.BASE64URL.encode(digest)
    private static String expectedUriString = DefaultJwkThumbprint.URI_PREFIX + alg.getId() + ":" + expectedToString
    private static URI expectedUri = URI.create(expectedUriString)

    private DefaultJwkThumbprint thumbprint

    @Before
    void setUp() {
        this.thumbprint = new DefaultJwkThumbprint(digest, alg)
    }

    @Test
    void testGetHashAlgorithm() {
        assertSame alg, thumbprint.getHashAlgorithm()
    }

    @Test
    void testToByteArray() {
        assertTrue MessageDigest.isEqual(digest, thumbprint.toByteArray())
    }

    @Test
    void testToURI() {
        assertEquals expectedUri, thumbprint.toURI()
    }

    @Test
    void testHashCode() {
        assertEquals io.jsonwebtoken.lang.Objects.nullSafeHashCode(digest, alg), thumbprint.hashCode()
    }

    @Test
    void testIdentityEquals() {
        assertEquals thumbprint, thumbprint
    }

    @Test
    void testPropertyEquals() {
        assertEquals thumbprint, new DefaultJwkThumbprint(digest, alg)
    }

    @Test
    void testNotEquals() {
        // invalid data type:
        assertNotEquals new DefaultJwkThumbprint(digest, alg), new Object()

        // same digest, different alg:
        assertFalse thumbprint == new DefaultJwkThumbprint(digest, DefaultHashAlgorithm.SHA1)

        // same alg, different digest:
        byte[] digest2 = alg.digest(new DefaultRequest<byte[]>("Hello World!".getBytes(StandardCharsets.UTF_8), null, null))
        assertFalse thumbprint == new DefaultJwkThumbprint(digest2, DefaultHashAlgorithm.SHA1)
    }

    @Test
    void testToString() {
        assertEquals expectedToString, thumbprint.toString()
    }
}
