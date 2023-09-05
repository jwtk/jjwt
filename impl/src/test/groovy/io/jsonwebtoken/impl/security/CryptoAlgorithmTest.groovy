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
package io.jsonwebtoken.impl.security

import org.junit.Test

import static org.junit.Assert.*

class CryptoAlgorithmTest {

    @Test
    void testEqualsSameInstance() {
        def alg = new TestCryptoAlgorithm()
        assertEquals alg, alg
    }

    @Test
    void testEqualsSameNameAndJcaName() {
        def alg1 = new TestCryptoAlgorithm()
        def alg2 = new TestCryptoAlgorithm()
        assertEquals alg1, alg2
    }

    @Test
    void testEqualsSameNameButDifferentJcaName() {
        def alg1 = new TestCryptoAlgorithm('test', 'test1')
        def alg2 = new TestCryptoAlgorithm('test', 'test2')
        assertNotEquals alg1, alg2
    }

    @Test
    void testEqualsOtherType() {
        assertNotEquals new TestCryptoAlgorithm(), new Object()
    }

    @Test
    void testToString() {
        assertEquals 'test', new TestCryptoAlgorithm().toString()
    }

    @Test
    void testHashCode() {
        int hash = 7
        hash = 31 * hash + 'test'.hashCode()
        hash = 31 * hash + 'jcaName'.hashCode()
        assertEquals hash, new TestCryptoAlgorithm().hashCode()
    }

    @Test
    void testEnsureSecureRandomWorksWithNullRequest() {
        def alg = new TestCryptoAlgorithm()
        def random = alg.ensureSecureRandom(null)
        assertSame Randoms.secureRandom(), random
    }

    class TestCryptoAlgorithm extends CryptoAlgorithm {
        TestCryptoAlgorithm() {
            this('test', 'jcaName')
        }

        TestCryptoAlgorithm(String id, String jcaName) {
            super(id, jcaName)
        }
    }
}
