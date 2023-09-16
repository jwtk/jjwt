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

import io.jsonwebtoken.lang.Registry
import io.jsonwebtoken.security.HashAlgorithm
import io.jsonwebtoken.security.Jwks
import org.junit.Test

import java.nio.charset.StandardCharsets

import static org.junit.Assert.*

class HashAlgorithmsTest {

    static final Registry<String, HashAlgorithm> reg = Jwks.HASH.get()

    static boolean contains(HashAlgorithm alg) {
        return reg.values().contains(alg)
    }

    @Test
    void testValues() {
        assertEquals 6, reg.values().size()
        assertTrue(contains(Jwks.HASH.SHA256)) // add more later
    }

    @Test
    void testForKey() {
        for (HashAlgorithm alg : reg.values()) {
            assertSame alg, reg.forKey(alg.getId())
        }
    }

    @Test
    void testForKeyCaseInsensitive() {
        for (HashAlgorithm alg : reg.values()) {
            assertSame alg, reg.forKey(alg.getId().toLowerCase())
        }
    }

    @Test(expected = IllegalArgumentException)
    void testForKeyWithInvalidId() {
        //unlike the 'get' paradigm, 'key' requires the value to exist
        reg.forKey('invalid')
    }

    @Test
    void testGet() {
        for (HashAlgorithm alg : reg.values()) {
            assertSame alg, reg.get(alg.getId())
        }
    }

    @Test
    void testGetCaseInsensitive() {
        for (HashAlgorithm alg : reg.values()) {
            assertSame alg, reg.get(alg.getId().toLowerCase())
        }
    }

    @Test
    void testGetWithInvalidId() {
        // 'get' paradigm can return null if not found
        assertNull reg.get('invalid')
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
