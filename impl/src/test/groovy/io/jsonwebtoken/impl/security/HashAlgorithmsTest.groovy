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

import io.jsonwebtoken.security.Algorithms
import io.jsonwebtoken.security.HashAlgorithm
import org.junit.Test

import static org.junit.Assert.*

class HashAlgorithmsTest {

    static boolean contains(HashAlgorithm alg) {
        return Algorithms.hash.values().contains(alg)
    }

    @Test
    void testValues() {
        assertEquals 1, Algorithms.hash.values().size()
        assertTrue(contains(Algorithms.hash.SHA256)) // add more later
    }

    @Test
    void testForId() {
        for (HashAlgorithm alg : Algorithms.hash.values()) {
            assertSame alg, Algorithms.hash.get(alg.getId())
        }
    }

    @Test
    void testForIdCaseInsensitive() {
        for (HashAlgorithm alg : Algorithms.hash.values()) {
            assertSame alg, Algorithms.hash.get(alg.getId().toLowerCase())
        }
    }

    @Test(expected = IllegalArgumentException)
    void testForIdWithInvalidId() {
        //unlike the 'find' paradigm, 'get' requires the value to exist
        Algorithms.hash.get('invalid')
    }

    @Test
    void testFindById() {
        for (HashAlgorithm alg : Algorithms.hash.values()) {
            assertSame alg, Algorithms.hash.find(alg.getId())
        }
    }

    @Test
    void testFindByIdCaseInsensitive() {
        for (HashAlgorithm alg : Algorithms.hash.values()) {
            assertSame alg, Algorithms.hash.find(alg.getId().toLowerCase())
        }
    }

    @Test
    void testFindByIdWithInvalidId() {
        // 'find' paradigm can return null if not found
        assertNull Algorithms.hash.find('invalid')
    }
}
