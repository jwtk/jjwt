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

import io.jsonwebtoken.impl.lang.FieldReadable
import io.jsonwebtoken.impl.lang.TestFieldReadable
import org.junit.Test

import java.security.spec.RSAOtherPrimeInfo

import static org.junit.Assert.assertFalse
import static org.junit.Assert.assertTrue

class DefaultRsaPrivateJwkTest {

    @Test
    void testEqualsOtherPrimesDifferentSizes() {
        def info1 = new RSAOtherPrimeInfo(BigInteger.ONE, BigInteger.ONE, BigInteger.ONE)
        def info2 = new RSAOtherPrimeInfo(BigInteger.TEN, BigInteger.TEN, BigInteger.TEN)
        FieldReadable a = new TestFieldReadable(value: [info1, info2])
        FieldReadable b = new TestFieldReadable(value: [info1]) // different sizes
        assertFalse DefaultRsaPrivateJwk.equalsOtherPrimes(a, b)
    }

    @Test
    void testEqualsOtherPrimes() {
        def info1 = new RSAOtherPrimeInfo(BigInteger.ONE, BigInteger.ONE, BigInteger.ONE)
        def info2 = new RSAOtherPrimeInfo(BigInteger.ONE, BigInteger.ONE, BigInteger.ONE)
        FieldReadable a = new TestFieldReadable(value: [info1])
        FieldReadable b = new TestFieldReadable(value: [info2])
        assertTrue DefaultRsaPrivateJwk.equalsOtherPrimes(a, b)
    }

    @Test
    void testEqualsOtherPrimesIdentity() {
        def info1 = new RSAOtherPrimeInfo(BigInteger.ONE, BigInteger.ONE, BigInteger.ONE)
        FieldReadable a = new TestFieldReadable(value: [info1])
        FieldReadable b = new TestFieldReadable(value: [info1])
        assertTrue DefaultRsaPrivateJwk.equalsOtherPrimes(a, b)
    }

    @Test
    void testEqualsOtherPrimesNullElement() {
        def info1 = new RSAOtherPrimeInfo(BigInteger.ONE, BigInteger.ONE, BigInteger.ONE)
        // sizes are the same, but one element is null:
        FieldReadable a = new TestFieldReadable(value: [null])
        FieldReadable b = new TestFieldReadable(value: [info1])
        assertFalse DefaultRsaPrivateJwk.equalsOtherPrimes(a, b)
    }

    @Test
    void testEqualsOtherPrimesInfoNotEqual() {
        def info1 = new RSAOtherPrimeInfo(BigInteger.ONE, BigInteger.ONE, BigInteger.ONE)
        def info2 = new RSAOtherPrimeInfo(BigInteger.ONE, BigInteger.ONE, BigInteger.TEN) // different
        FieldReadable a = new TestFieldReadable(value: [info1])
        FieldReadable b = new TestFieldReadable(value: [info2])
        assertFalse DefaultRsaPrivateJwk.equalsOtherPrimes(a, b)
    }

}
