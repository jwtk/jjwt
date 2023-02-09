/*
 * Copyright (C) 2020 jsonwebtoken.io
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

import java.security.Key

import static org.junit.Assert.*

/**
 * Tests {@link Algorithms#key} values.
 *
 * @since JJWT_RELEASE_VERSION
 */
class KeyAlgorithmsTest {

    static boolean contains(KeyAlgorithm<? extends Key, ? extends Key> alg) {
        return Algorithms.key.values().contains(alg)
    }

    @Test
    void testValues() {
        assertEquals 17, Algorithms.key.values().size()
        assertTrue(contains(Algorithms.key.DIRECT) &&
                contains(Algorithms.key.A128KW) &&
                contains(Algorithms.key.A192KW) &&
                contains(Algorithms.key.A256KW) &&
                contains(Algorithms.key.A128GCMKW) &&
                contains(Algorithms.key.A192GCMKW) &&
                contains(Algorithms.key.A256GCMKW) &&
                contains(Algorithms.key.PBES2_HS256_A128KW) &&
                contains(Algorithms.key.PBES2_HS384_A192KW) &&
                contains(Algorithms.key.PBES2_HS512_A256KW) &&
                contains(Algorithms.key.RSA1_5) &&
                contains(Algorithms.key.RSA_OAEP) &&
                contains(Algorithms.key.RSA_OAEP_256) &&
                contains(Algorithms.key.ECDH_ES) &&
                contains(Algorithms.key.ECDH_ES_A128KW) &&
                contains(Algorithms.key.ECDH_ES_A192KW) &&
                contains(Algorithms.key.ECDH_ES_A256KW)
        )
    }

    @Test
    void testForId() {
        for (KeyAlgorithm alg : Algorithms.key.values()) {
            assertSame alg, Algorithms.key.get(alg.getId())
        }
    }

    @Test
    void testForIdCaseInsensitive() {
        for (KeyAlgorithm alg : Algorithms.key.values()) {
            assertSame alg, Algorithms.key.get(alg.getId().toLowerCase())
        }
    }

    @Test(expected = IllegalArgumentException)
    void testForIdWithInvalidId() {
        //unlike the 'find' paradigm, 'get' requires the value to exist
        Algorithms.key.get('invalid')
    }

    @Test
    void testFindById() {
        for (KeyAlgorithm alg : Algorithms.key.values()) {
            assertSame alg, Algorithms.key.find(alg.getId())
        }
    }

    @Test
    void testFindByIdCaseInsensitive() {
        for (KeyAlgorithm alg : Algorithms.key.values()) {
            assertSame alg, Algorithms.key.find(alg.getId().toLowerCase())
        }
    }

    @Test
    void testFindByIdWithInvalidId() {
        // 'find' paradigm can return null if not found
        assertNull Algorithms.key.find('invalid')
    }

    /*
    @Test
    @Ignore // temporarily until we decide if this API will remain
    void testEstimateIterations() {
        // keep it super short so we don't hammer the test server or slow down the build too much:
        long desiredMillis = 50
        int result = Algorithms.key.estimateIterations(Algorithms.key.PBES2_HS256_A128KW, desiredMillis)
        assertTrue result > Pbes2HsAkwAlgorithm.MIN_RECOMMENDED_ITERATIONS
    }
     */
}
