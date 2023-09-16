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
        return Jwts.KEY.get().values().contains(alg)
    }

    @Test
    void testValues() {
        assertEquals 17, Jwts.KEY.get().values().size()
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
    void testForKey() {
        for (KeyAlgorithm alg : Jwts.KEY.get().values()) {
            assertSame alg, Jwts.KEY.get().forKey(alg.getId())
        }
    }

    @Test
    void testForKeyCaseInsensitive() {
        for (KeyAlgorithm alg : Jwts.KEY.get().values()) {
            assertSame alg, Jwts.KEY.get().forKey(alg.getId().toLowerCase())
        }
    }

    @Test(expected = IllegalArgumentException)
    void testForKeyWithInvalidId() {
        //unlike the 'get' paradigm, 'key' requires the value to exist
        Jwts.KEY.get().forKey('invalid')
    }

    @Test
    void testGet() {
        for (KeyAlgorithm alg : Jwts.KEY.get().values()) {
            assertSame alg, Jwts.KEY.get().get(alg.getId())
        }
    }

    @Test
    void testGetCaseInsensitive() {
        for (KeyAlgorithm alg : Jwts.KEY.get().values()) {
            assertSame alg, Jwts.KEY.get().get(alg.getId().toLowerCase())
        }
    }

    @Test
    void testGetWithInvalidId() {
        // 'get' paradigm can return null if not found
        assertNull Jwts.KEY.get().get('invalid')
    }
}
