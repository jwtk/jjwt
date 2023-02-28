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

import io.jsonwebtoken.Jwts
import org.junit.Test

import java.security.Key

import static org.junit.Assert.*

/**
 * Tests {@link Jwts#KEY} values.
 *
 * @since JJWT_RELEASE_VERSION
 */
class KeyAlgorithmsTest {

    static boolean contains(KeyAlgorithm<? extends Key, ? extends Key> alg) {
        return Jwts.KEY.values().contains(alg)
    }

    @Test
    void testValues() {
        assertEquals 17, Jwts.KEY.values().size()
        assertTrue(contains(Jwts.KEY.DIRECT) &&
                contains(Jwts.KEY.A128KW) &&
                contains(Jwts.KEY.A192KW) &&
                contains(Jwts.KEY.A256KW) &&
                contains(Jwts.KEY.A128GCMKW) &&
                contains(Jwts.KEY.A192GCMKW) &&
                contains(Jwts.KEY.A256GCMKW) &&
                contains(Jwts.KEY.PBES2_HS256_A128KW) &&
                contains(Jwts.KEY.PBES2_HS384_A192KW) &&
                contains(Jwts.KEY.PBES2_HS512_A256KW) &&
                contains(Jwts.KEY.RSA1_5) &&
                contains(Jwts.KEY.RSA_OAEP) &&
                contains(Jwts.KEY.RSA_OAEP_256) &&
                contains(Jwts.KEY.ECDH_ES) &&
                contains(Jwts.KEY.ECDH_ES_A128KW) &&
                contains(Jwts.KEY.ECDH_ES_A192KW) &&
                contains(Jwts.KEY.ECDH_ES_A256KW)
        )
    }

    @Test
    void testForId() {
        for (KeyAlgorithm alg : Jwts.KEY.values()) {
            assertSame alg, Jwts.KEY.get(alg.getId())
        }
    }

    @Test
    void testForIdCaseInsensitive() {
        for (KeyAlgorithm alg : Jwts.KEY.values()) {
            assertSame alg, Jwts.KEY.get(alg.getId().toLowerCase())
        }
    }

    @Test(expected = IllegalArgumentException)
    void testForIdWithInvalidId() {
        //unlike the 'find' paradigm, 'get' requires the value to exist
        Jwts.KEY.get('invalid')
    }

    @Test
    void testFindById() {
        for (KeyAlgorithm alg : Jwts.KEY.values()) {
            assertSame alg, Jwts.KEY.find(alg.getId())
        }
    }

    @Test
    void testFindByIdCaseInsensitive() {
        for (KeyAlgorithm alg : Jwts.KEY.values()) {
            assertSame alg, Jwts.KEY.find(alg.getId().toLowerCase())
        }
    }

    @Test
    void testFindByIdWithInvalidId() {
        // 'find' paradigm can return null if not found
        assertNull Jwts.KEY.find('invalid')
    }

    /*
    @Test
    @Ignore // temporarily until we decide if this API will remain
    void testEstimateIterations() {
        // keep it super short so we don't hammer the test server or slow down the build too much:
        long desiredMillis = 50
        int result = Jwts.KEY.estimateIterations(Jwts.KEY.PBES2_HS256_A128KW, desiredMillis)
        assertTrue result > Pbes2HsAkwAlgorithm.MIN_RECOMMENDED_ITERATIONS
    }
     */
}
