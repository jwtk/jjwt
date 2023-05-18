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
package io.jsonwebtoken.security

import io.jsonwebtoken.Jwts
import org.junit.Test

import static org.junit.Assert.*

class StandardSecureDigestAlgorithmsTest {

    @Test
    void testGet() {
        for (SecureDigestAlgorithm alg : Jwts.SIG.values()) {
            assertSame alg, Jwts.SIG.get(alg.getId())
        }
    }

    @Test
    void testGetCaseInsensitive() {
        for (SecureDigestAlgorithm alg : Jwts.SIG.values()) {
            assertSame alg, Jwts.SIG.get(alg.getId().toLowerCase())
        }
    }

    @Test(expected = IllegalArgumentException)
    void testGetWithInvalidId() {
        //unlike the 'find' paradigm, 'for' requires the value to exist
        Jwts.SIG.get('invalid')
    }

    @Test
    void testFindById() {
        for (SecureDigestAlgorithm alg : Jwts.SIG.values()) {
            assertSame alg, Jwts.SIG.find(alg.getId())
        }
    }

    @Test
    void testFindByIdCaseInsensitive() {
        for (SecureDigestAlgorithm alg : Jwts.SIG.values()) {
            assertSame alg, Jwts.SIG.find(alg.getId().toLowerCase())
        }
    }

    @Test
    void testFindByIdWithInvalidId() {
        // 'find' paradigm can return null if not found
        assertNull Jwts.SIG.find('invalid')
    }

    @Test
    void testFindEd448() {
        assertNotNull Jwts.SIG.find('Ed448')
    }

    @Test
    void testFindEd448CaseInsensitive() {
        assertNotNull Jwts.SIG.find('ED448')
        assertNotNull Jwts.SIG.find('ed448')
    }

    @Test
    void testFindEd25519() {
        assertNotNull Jwts.SIG.find('Ed25519')
    }

    @Test
    void testFindEd25519CaseInsensitive() {
        assertNotNull Jwts.SIG.find('ED25519')
        assertNotNull Jwts.SIG.find('ed25519')
    }
}
