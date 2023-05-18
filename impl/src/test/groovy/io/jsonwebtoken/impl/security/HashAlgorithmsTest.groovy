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

import io.jsonwebtoken.security.HashAlgorithm
import io.jsonwebtoken.security.Jwks
import org.junit.Test

import java.nio.charset.StandardCharsets

import static org.junit.Assert.*

class HashAlgorithmsTest {

    static boolean contains(HashAlgorithm alg) {
        return Jwks.HASH.values().contains(alg)
    }

    @Test
    void testValues() {
        assertEquals 6, Jwks.HASH.values().size()
        assertTrue(contains(Jwks.HASH.SHA256)) // add more later
    }

    @Test
    void testForId() {
        for (HashAlgorithm alg : Jwks.HASH.values()) {
            assertSame alg, Jwks.HASH.get(alg.getId())
        }
    }

    @Test
    void testForIdCaseInsensitive() {
        for (HashAlgorithm alg : Jwks.HASH.values()) {
            assertSame alg, Jwks.HASH.get(alg.getId().toLowerCase())
        }
    }

    @Test(expected = IllegalArgumentException)
    void testForIdWithInvalidId() {
        //unlike the 'find' paradigm, 'get' requires the value to exist
        Jwks.HASH.get('invalid')
    }

    @Test
    void testFindById() {
        for (HashAlgorithm alg : Jwks.HASH.values()) {
            assertSame alg, Jwks.HASH.find(alg.getId())
        }
    }

    @Test
    void testFindByIdCaseInsensitive() {
        for (HashAlgorithm alg : Jwks.HASH.values()) {
            assertSame alg, Jwks.HASH.find(alg.getId().toLowerCase())
        }
    }

    @Test
    void testFindByIdWithInvalidId() {
        // 'find' paradigm can return null if not found
        assertNull Jwks.HASH.find('invalid')
    }

    static DefaultRequest<byte[]> request(String msg) {
        byte[] data = msg.getBytes(StandardCharsets.UTF_8)
        return new DefaultRequest<byte[]>(data, null, null)
    }

    static void testSha(HashAlgorithm alg) {
        String id = alg.getId()
        int c = ('-' as char) as int
        def digestLength = id.substring(id.lastIndexOf(c) + 1) as int
        assertTrue alg.getJcaName().endsWith('' + digestLength)
        def digest = alg.digest(request("hello"))
        assertEquals digestLength, (digest.length * Byte.SIZE)
    }

    @Test
    void testSha256() {
        testSha(Jwks.HASH.SHA256)
    }

    @Test
    void testSha384() {
        testSha(Jwks.HASH.SHA384)
    }

    @Test
    void testSha512() {
        testSha(Jwks.HASH.SHA512)
    }

    @Test
    void testSha3_256() {
        testSha(Jwks.HASH.SHA3_256)
    }

    @Test
    void testSha3_384() {
        testSha(Jwks.HASH.SHA3_384)
    }

    @Test
    void testSha3_512() {
        testSha(Jwks.HASH.SHA3_512)
    }
}
