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

import io.jsonwebtoken.Jwe
import io.jsonwebtoken.Jws
import io.jsonwebtoken.Jwts
import io.jsonwebtoken.lang.Registry
import org.junit.Test

import static org.junit.Assert.*

class StandardAlgorithmsTest {

    static final List<Registry<String, ?>> registries = [Jws.alg.registry(), Jwe.alg.registry(), Jwe.enc.registry(), Jwts.ZIP.get(), Jwks.HASH.get()]

    private static void eachRegAlg(Closure c) {
        registries.each { reg -> reg.values().each { c(reg, it) } }
    }

    @Test
    void testSize() {
        assertEquals 14, Jws.alg.registry().size()
        assertEquals 6, Jwe.alg.registry().size()
        assertEquals 17, Jwe.enc.registry().size()
        assertEquals 2, Jwts.ZIP.get().size()
        assertEquals 6, Jwks.HASH.get().size()
    }

    @Test
    void testForKey() {
        eachRegAlg { reg, alg ->
            assertSame alg, reg.forKey(alg.getId())
        }
    }

    @Test
    void testForKeyWithInvalidId() {
        //unlike the 'get' paradigm, 'forKey' requires the value to exist
        registries.each { reg ->
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
    void testGetWithInvalidId() {
        // 'get' paradigm can return null if not found
        registries.each { reg ->
            assertNull reg.get('invalid')
        }
    }

    @SuppressWarnings('GroovyUnusedCatchParameter')
    @Test
    void testGetWithoutStringKey() {
        registries.each { reg ->
            try {
                assertNull reg.get(2) // not a string, should fail
                fail()
            } catch (ClassCastException expected) { // allowed per Map#get contract
            }
        }
    }

}
