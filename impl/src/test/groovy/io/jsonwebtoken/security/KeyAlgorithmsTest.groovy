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
 * Tests {@link Jwe.enc} values.
 *
 * @since 0.12.0
 */
class KeyAlgorithmsTest {

    static boolean contains(KeyAlgorithm<? extends Key, ? extends Key> alg) {
        return Jwe.enc.registry().values().contains(alg)
    }

    @Test
    void testValues() {
        assertEquals 17, Jwe.enc.registry().values().size()
        assertTrue(contains(Jwe.enc.DIRECT) &&
                contains(Jwe.enc.A128KW) &&
                contains(Jwe.enc.A192KW) &&
                contains(Jwe.enc.A256KW) &&
                contains(Jwe.enc.A128GCMKW) &&
                contains(Jwe.enc.A192GCMKW) &&
                contains(Jwe.enc.A256GCMKW) &&
                contains(Jwe.enc.PBES2_HS256_A128KW) &&
                contains(Jwe.enc.PBES2_HS384_A192KW) &&
                contains(Jwe.enc.PBES2_HS512_A256KW) &&
                contains(Jwe.enc.RSA1_5) &&
                contains(Jwe.enc.RSA_OAEP) &&
                contains(Jwe.enc.RSA_OAEP_256) &&
                contains(Jwe.enc.ECDH_ES) &&
                contains(Jwe.enc.ECDH_ES_A128KW) &&
                contains(Jwe.enc.ECDH_ES_A192KW) &&
                contains(Jwe.enc.ECDH_ES_A256KW)
        )
    }

    @Test
    void testForKey() {
        for (KeyAlgorithm alg : Jwe.enc.registry().values()) {
            assertSame alg, Jwe.enc.registry().forKey(alg.getId())
        }
    }

    @Test(expected = IllegalArgumentException)
    void testForKeyWithInvalidId() {
        //unlike the 'get' paradigm, 'key' requires the value to exist
        Jwe.enc.registry().forKey('invalid')
    }

    @Test
    void testGet() {
        for (KeyAlgorithm alg : Jwe.enc.registry().values()) {
            assertSame alg, Jwe.enc.registry().get(alg.getId())
        }
    }

    @Test
    void testGetWithInvalidId() {
        // 'get' paradigm can return null if not found
        assertNull Jwe.enc.registry().get('invalid')
    }
}
