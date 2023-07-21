/*
 * Copyright (C) 2023 jsonwebtoken.io
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
import io.jsonwebtoken.lang.Registry
import org.junit.Test

import static org.junit.Assert.*

class StandardAlgorithmsTest {

    static def registries = [Jwts.SIG, Jwts.ENC, Jwts.KEY, Jwks.HASH] as List<Registry<String, ?>>

    @Test
    void testSize() {
        assertEquals 14, Jwts.SIG.size()
        assertEquals 6, Jwts.ENC.size()
        assertEquals 17, Jwts.KEY.size()
        assertEquals 6, Jwks.HASH.size()
    }

    private static void eachRegAlg(Closure c) {
        registries.each { reg -> reg.values().each { c(reg, it) } }
    }

    @Test
    void testForKey() {
        eachRegAlg { reg, alg ->
            assertSame alg, reg.forKey(alg.getId())
        }
    }

    @Test
    void testForKeyCaseInsensitive() {
        eachRegAlg { reg, alg ->
            assertSame alg, reg.forKey(alg.getId().toLowerCase())
        }
    }

    @Test
    void testForKeyWithInvalidId() {
        //unlike the 'get' paradigm, 'forKey' requires the value to exist
        registries.each {reg ->
            //noinspection GroovyUnusedCatchParameter
            try {
                reg.forKey('invalid')
                fail()
            } catch (IllegalArgumentException expected) {
            }
        }
    }

    @Test
    void testGet() {
        eachRegAlg { reg, alg ->
            assertSame alg, reg.get(alg.getId())
        }
    }

    @Test
    void testGetCaseInsensitive() {
        eachRegAlg { reg, alg ->
            assertSame alg, reg.get(alg.getId().toLowerCase())
        }
    }

    @Test
    void testGetWithInvalidId() {
        // 'get' paradigm can return null if not found
        registries.each {reg ->
            assertNull reg.get('invalid')
        }
    }

}
