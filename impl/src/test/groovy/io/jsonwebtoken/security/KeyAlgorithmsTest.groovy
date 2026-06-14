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

import io.jsonwebtoken.Jwe
import org.junit.Test

import java.security.Key

import static org.junit.Assert.*

/**
 * Tests {@link Jwe.alg} values.
 *
 * @since 0.12.0
 */
class KeyAlgorithmsTest {

    static boolean contains(KeyAlgorithm<? extends Key, ? extends Key> alg) {
        return Jwe.alg.registry().values().contains(alg)
    }

    @Test
    void testValues() {
        assertEquals 17, Jwe.alg.registry().values().size()
        assertTrue(contains(Jwe.alg.DIRECT) &&
                contains(Jwe.alg.A128KW) &&
                contains(Jwe.alg.A192KW) &&
                contains(Jwe.alg.A256KW) &&
                contains(Jwe.alg.A128GCMKW) &&
                contains(Jwe.alg.A192GCMKW) &&
                contains(Jwe.alg.A256GCMKW) &&
                contains(Jwe.alg.PBES2_HS256_A128KW) &&
                contains(Jwe.alg.PBES2_HS384_A192KW) &&
                contains(Jwe.alg.PBES2_HS512_A256KW) &&
                contains(Jwe.alg.RSA1_5) &&
                contains(Jwe.alg.RSA_OAEP) &&
                contains(Jwe.alg.RSA_OAEP_256) &&
                contains(Jwe.alg.ECDH_ES) &&
                contains(Jwe.alg.ECDH_ES_A128KW) &&
                contains(Jwe.alg.ECDH_ES_A192KW) &&
                contains(Jwe.alg.ECDH_ES_A256KW)
        )
    }

    @Test
    void testForKey() {
        for (KeyAlgorithm alg : Jwe.alg.registry().values()) {
            assertSame alg, Jwe.alg.registry().forKey(alg.getId())
        }
    }

    @Test(expected = IllegalArgumentException)
    void testForKeyWithInvalidId() {
        //unlike the 'get' paradigm, 'key' requires the value to exist
        Jwe.alg.registry().forKey('invalid')
    }

    @Test
    void testGet() {
        for (KeyAlgorithm alg : Jwe.alg.registry().values()) {
            assertSame alg, Jwe.alg.registry().get(alg.getId())
        }
    }

    @Test
    void testGetWithInvalidId() {
        // 'get' paradigm can return null if not found
        assertNull Jwe.alg.registry().get('invalid')
    }
}
