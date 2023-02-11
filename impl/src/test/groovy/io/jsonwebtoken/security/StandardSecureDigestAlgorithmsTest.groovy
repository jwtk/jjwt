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

import org.junit.Test

import static org.junit.Assert.*

class StandardSecureDigestAlgorithmsTest {

    @Test
    void testGet() {
        for (SecureDigestAlgorithm alg : Algorithms.sig.values()) {
            assertSame alg, Algorithms.sig.get(alg.getId())
        }
    }

    @Test
    void testGetCaseInsensitive() {
        for (SecureDigestAlgorithm alg : Algorithms.sig.values()) {
            assertSame alg, Algorithms.sig.get(alg.getId().toLowerCase())
        }
    }

    @Test(expected = IllegalArgumentException)
    void testGetWithInvalidId() {
        //unlike the 'find' paradigm, 'for' requires the value to exist
        Algorithms.sig.get('invalid')
    }

    @Test
    void testFindById() {
        for (SecureDigestAlgorithm alg : Algorithms.sig.values()) {
            assertSame alg, Algorithms.sig.find(alg.getId())
        }
    }

    @Test
    void testFindByIdCaseInsensitive() {
        for (SecureDigestAlgorithm alg : Algorithms.sig.values()) {
            assertSame alg, Algorithms.sig.find(alg.getId().toLowerCase())
        }
    }

    @Test
    void testFindByIdWithInvalidId() {
        // 'find' paradigm can return null if not found
        assertNull Algorithms.sig.find('invalid')
    }

    @Test
    void testFindEd448() {
        assertNotNull Algorithms.sig.find('Ed448')
    }

    @Test
    void testFindEd448CaseInsensitive() {
        assertNotNull Algorithms.sig.find('ED448')
        assertNotNull Algorithms.sig.find('ed448')
    }

    @Test
    void testFindEd25519() {
        assertNotNull Algorithms.sig.find('Ed25519')
    }

    @Test
    void testFindEd25519CaseInsensitive() {
        assertNotNull Algorithms.sig.find('ED25519')
        assertNotNull Algorithms.sig.find('ed25519')
    }
}
