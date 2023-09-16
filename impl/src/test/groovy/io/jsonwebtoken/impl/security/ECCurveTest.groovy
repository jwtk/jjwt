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
package io.jsonwebtoken.impl.security


import org.junit.Test

import java.security.PublicKey
import java.security.interfaces.ECPublicKey
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint
import java.security.spec.EllipticCurve

import static org.junit.Assert.*

class ECCurveTest {

    static void assertContains(ECCurve curve, PublicKey pub) {
        assertTrue(curve.contains(pub))
    }

    @Test
    void testContainsKeyTrue() {
        assertContains(ECCurve.P256, TestKeys.ES256.pair.public)
        assertContains(ECCurve.P384, TestKeys.ES384.pair.public)
        assertContains(ECCurve.P521, TestKeys.ES512.pair.public)
    }

    @Test
    void testContainsKeyNull() {
        ECCurve.VALUES.each {
            assertFalse(it.contains(null))
        }
    }

    @Test
    void testContainsNonECPublicKey() {
        ECCurve.VALUES.each {
            assertFalse it.contains(TestKeys.HS256)
        }
    }

    @Test
    void testContainsKeyNullParams() {
        ECCurve.VALUES.each {
            assertFalse it.contains(new TestECPublicKey())
        }
    }

    @Test
    void testContainsKeyNullJcaCurve() {
        def src = TestKeys.ES256.pair.public.getParams() as ECParameterSpec
        def spec = new ECParameterSpec(src.curve, src.generator, src.order, src.cofactor) {
            @Override
            EllipticCurve getCurve() {
                return null
            }
        }
        def key = new TestECKey(params: spec)
        ECCurve.VALUES.each {
            assertFalse it.contains(key)
        }
    }

    @Test
    void testContainsKeyBadWPoint() {
        ECCurve.VALUES.each {
            def src = it.keyPair().build().public
            def spec = src.getParams() as ECParameterSpec
            def key = new TestECPublicKey(params: spec, w: new ECPoint(BigInteger.ONE, BigInteger.ONE))
            assertFalse it.contains(key)
        }
    }

    @Test
    void testContainsTrue() {
        ECCurve curve = ECCurve.P256
        def pair = curve.keyPair().build()
        ECPublicKey ecPub = (ECPublicKey) pair.getPublic()
        assertTrue(curve.contains(ecPub.getW()))
    }

    @Test
    void testContainsFalse() {
        assertFalse(ECCurve.P256.contains(new ECPoint(BigInteger.ONE, BigInteger.ONE)))
    }

    @Test
    void testFindByJcaEllipticCurve() {
        ECCurve.VALUES.each {
            it.equals(ECCurve.findByJcaCurve(it.toParameterSpec().getCurve()))
        }
    }

    @Test
    void testMultiplyInfinity() {
        ECCurve.VALUES.each {
            def result = it.multiply(ECPoint.POINT_INFINITY, BigInteger.valueOf(1))
            assertEquals ECPoint.POINT_INFINITY, result

        }
    }

    @Test
    void testDoubleInfinity() {
        ECCurve.VALUES.each {
            def result = it.doublePoint(ECPoint.POINT_INFINITY)
            assertEquals ECPoint.POINT_INFINITY, result
        }
    }

    @Test
    void testAddInfinity() {
        ECCurve.VALUES.each {
            def curve = it.spec.getCurve()
            ECPoint point = new ECPoint(BigInteger.valueOf(1), BigInteger.valueOf(2)) // any point is fine for this test
            def result = it.add(ECPoint.POINT_INFINITY, point)
            //adding infinity to a point should return the point:
            assertEquals point, result
            //adding a point to infinity should return the point:
            result = it.add(point, ECPoint.POINT_INFINITY)
            assertEquals point, result
        }
    }

    @Test
    void testAddSamePointDoublesIt() {
        ECCurve.VALUES.each {
            def pair = it.keyPair().build()
            def pub = pair.getPublic() as ECPublicKey
            def point = pub.getW()
            def doubled = it.doublePoint(point)
            def added = it.add(point, point)
            assertEquals doubled, added
        }
    }

    @Test
    void testFindByKeyNull() {
        assertNull ECCurve.findByKey(null)
    }

    @Test
    void testFindByKeyNotECKey() {
        assertNull ECCurve.findByKey(TestKeys.HS256)
    }

    @Test
    void testFindByKeyNullParams() {
        assertNull ECCurve.findByKey(new TestECKey())
    }

    @Test
    void testFindByKeyNullJcaCurve() {
        def src = TestKeys.ES256.pair.public.getParams() as ECParameterSpec
        def spec = new ECParameterSpec(src.curve, src.generator, src.order, src.cofactor) {
            @Override
            EllipticCurve getCurve() {
                return null
            }
        }
        assertNull ECCurve.findByKey(new TestECKey(params: spec))
    }

    @Test
    void testFindByKeyWithNullWPoint() {
        def spec = TestKeys.ES256.pair.public.getParams() as ECParameterSpec
        assertNull ECCurve.findByKey(new TestECPublicKey(params: spec))
    }

    @Test
    void testFindByKeyWithWPointNotOnCurve() {
        def spec = TestKeys.ES256.pair.public.getParams() as ECParameterSpec
        def key = new TestECPublicKey(params: spec, w: new ECPoint(BigInteger.ONE, BigInteger.ONE))
        assertNull ECCurve.findByKey(key)
    }
}
