/*
 * Copyright (C) 2015 jsonwebtoken.io
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
package io.jsonwebtoken.impl


import io.jsonwebtoken.impl.lang.Parameter
import io.jsonwebtoken.impl.lang.Parameters
import io.jsonwebtoken.impl.security.Randoms
import io.jsonwebtoken.lang.Collections
import io.jsonwebtoken.lang.Registry
import org.junit.Before
import org.junit.Test

import static org.junit.Assert.*

class ParameterMapTest {

    private static final Parameter<String> DUMMY = Parameters.string('' + Randoms.secureRandom().nextInt(), "RANDOM")
    private static final Parameter<BigInteger> SECRET = Parameters.secretBigInt('foo', 'foo')
    private static final Set<Parameter<?>> PARAM_SET = Collections.setOf(DUMMY)
    private static final Registry<String, Parameter<?>> PARAMS = Parameters.registry(PARAM_SET)
    ParameterMap jwtMap

    @Before
    void setup() {
        // dummy param to satisfy constructor:
        jwtMap = new ParameterMap(PARAMS)
    }

    void unsupported(Closure<?> c) {
        try {
            c()
            fail("Should have thrown")
        } catch (UnsupportedOperationException expected) {
            String msg = "${jwtMap.getName()} instance is immutable and may not be modified."
            assertEquals msg, expected.getMessage()
        }
    }

    @Test
    void testImmutable() {
        Map mutable = jwtMap
        mutable.put('foo', 'bar')
        Map immutable = new ParameterMap(PARAMS, mutable) // make immutable

        unsupported { immutable.put('whatever', 'value') }
        unsupported { immutable.putAll([a: 'b']) }
        unsupported { immutable.remove('foo') }
        unsupported { immutable.clear() }

        mutable.clear() // no exception
        assertEquals 0, mutable.size()
    }

    @Test
    void testContainsKey() {
        jwtMap.put('foo', 'bar')
        assertTrue jwtMap.containsKey('foo')
    }

    @Test
    void testContainsValue() {
        jwtMap.put('foo', 'bar')
        assertTrue jwtMap.containsValue('bar')
    }

    @Test
    void testRemoveByPuttingNull() {
        jwtMap.put('foo', 'bar')
        assertTrue jwtMap.containsKey('foo')
        assertTrue jwtMap.containsValue('bar')
        jwtMap.put('foo', null)
        assertFalse jwtMap.containsKey('foo')
        assertFalse jwtMap.containsValue('bar')
    }

    @Test
    void testPutAll() {
        jwtMap.putAll([a: 'b', c: 'd'])
        assertEquals jwtMap.size(), 2
        assertEquals jwtMap.a, 'b'
        assertEquals jwtMap.c, 'd'
    }

    @Test
    void testPutAllWithNullArgument() {
        jwtMap.putAll((Map) null)
        assertEquals jwtMap.size(), 0
    }

    @Test
    void testClear() {
        jwtMap.put('foo', 'bar')
        assertEquals jwtMap.size(), 1
        jwtMap.clear()
        assertEquals jwtMap.size(), 0
    }

    @Test
    void testKeySet() {
        jwtMap.putAll([a: 'b', c: 'd'])
        assertEquals(jwtMap.keySet(), ['a', 'c'] as Set)
    }

    @Test
    void testValues() {
        jwtMap.putAll([a: 'b', c: 'd'])
        def s = ['b', 'd']
        assertTrue jwtMap.values().containsAll(s) && s.containsAll(jwtMap.values())
    }

    @Test
    void testEquals() throws Exception {
        def m1 = new ParameterMap(PARAMS)
        m1.put("a", "a")

        def m2 = new ParameterMap(PARAMS)
        m2.put("a", "a")

        assertEquals(m1, m2)
    }

    @Test
    void testHashcode() throws Exception {
        def hashCodeEmpty = jwtMap.hashCode()

        jwtMap.put("a", "b")
        def hashCodeNonEmpty = jwtMap.hashCode()
        assertTrue(hashCodeEmpty != hashCodeNonEmpty)

        def identityHash = System.identityHashCode(jwtMap)
        assertTrue(hashCodeNonEmpty != identityHash)
    }

    @Test
    void testGetName() {
        def map = new ParameterMap(PARAMS)
        assertEquals 'Map', map.getName()
    }

    @Test
    void testSetSecretFieldWithInvalidTypeValue() {
        def map = new ParameterMap(Parameters.registry(SECRET))
        def invalidValue = URI.create('https://whatever.com')
        try {
            map.put('foo', invalidValue)
            fail()
        } catch (IllegalArgumentException expected) {
            //Ensure <redacted> message so we don't show any secret value:
            String msg = 'Invalid Map \'foo\' (foo) value: <redacted>. Values must be ' +
                    'either String or java.math.BigInteger instances. Value type found: ' +
                    'java.net.URI.'
            assertEquals msg, expected.getMessage()
        }
    }

    @Test(expected = IllegalStateException)
    void testIteratorRemoveWithoutIteration() {
        jwtMap.iterator().remove()
    }
}
