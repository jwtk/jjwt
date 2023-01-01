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

import static org.junit.Assert.assertNull
import static org.junit.Assert.assertSame

class JwsAlgorithmsTest {

    @Test
    void testPrivateCtor() { // for code coverage only
        new JwsAlgorithms()
    }

    @Test
    void testForId() {
        for (SecureDigestAlgorithm alg : JwsAlgorithms.values()) {
            assertSame alg, JwsAlgorithms.forId(alg.getId())
        }
    }

    @Test
    void testForIdCaseInsensitive() {
        for (SecureDigestAlgorithm alg : JwsAlgorithms.values()) {
            assertSame alg, JwsAlgorithms.forId(alg.getId().toLowerCase())
        }
    }

    @Test(expected = IllegalArgumentException)
    void testForIdWithInvalidId() {
        //unlike the 'find' paradigm, 'for' requires the value to exist
        JwsAlgorithms.forId('invalid')
    }

    @Test
    void testFindById() {
        for (SecureDigestAlgorithm alg : JwsAlgorithms.values()) {
            assertSame alg, JwsAlgorithms.findById(alg.getId())
        }
    }

    @Test
    void testFindByIdCaseInsensitive() {
        for (SecureDigestAlgorithm alg : JwsAlgorithms.values()) {
            assertSame alg, JwsAlgorithms.findById(alg.getId().toLowerCase())
        }
    }

    @Test
    void testFindByIdWithInvalidId() {
        // 'find' paradigm can return null if not found
        assertNull JwsAlgorithms.findById('invalid')
    }
}
