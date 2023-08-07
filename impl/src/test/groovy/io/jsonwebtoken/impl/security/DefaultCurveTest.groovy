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

import org.junit.Before
import org.junit.Test

import static org.junit.Assert.*

class DefaultCurveTest {

    DefaultCurve curve

    @Before
    void setUp() {
        curve = new DefaultCurve('foo', 'bar')
    }

    @Test
    void testGetId() {
        assertEquals 'foo', curve.getId()
    }

    @Test
    void testGetJcaName() {
        assertEquals 'bar', curve.getJcaName()
    }

    @Test
    void testHashcode() {
        assertEquals 'foo'.hashCode(), curve.hashCode()
    }

    @Test
    void testToString() {
        assertEquals 'foo', curve.toString()
    }

    @Test
    void testEqualsIdentity() {
        //noinspection ChangeToOperator
        assertTrue curve.equals(curve)
    }

    @Test
    void testEqualsTypeMismatch() {
        Object obj = new Integer(42)
        //noinspection ChangeToOperator
        assertFalse curve.equals(obj);
    }

    @Test
    void testEqualsId() {
        def other = new DefaultCurve('foo', 'asdfasdf')
        //noinspection ChangeToOperator
        assertTrue curve.equals(other)
    }

    @Test
    void testNotEquals() {
        def other = new DefaultCurve('abc', 'bar')
        //noinspection ChangeToOperator
        assertFalse curve.equals(other)
    }

    @Test
    void testKeyPairBuilder() {
        def builder = curve.keyPair()
        assertEquals 'bar', builder.jcaName //builder is an instanceof DefaultKeyPairBuilder
    }
}
