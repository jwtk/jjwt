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

import io.jsonwebtoken.impl.lang.Field
import io.jsonwebtoken.impl.lang.Fields
import io.jsonwebtoken.impl.security.Randoms
import io.jsonwebtoken.lang.Collections
import io.jsonwebtoken.lang.Registry
import org.junit.Before
import org.junit.Test

import static org.junit.Assert.*

class FieldMapTest {

    private static final Field<String> DUMMY = Fields.string('' + Randoms.secureRandom().nextInt(), "RANDOM")
    private static final Field<BigInteger> SECRET = Fields.secretBigInt('foo', 'foo')
    private static final Set<Field<?>> FIELD_SET = Collections.setOf(DUMMY)
    private static final Registry<String, Field<?>> FIELDS = Fields.registry(FIELD_SET)
    FieldMap jwtMap

    @Before
    void setup() {
        // dummy field to satisfy constructor:
        jwtMap = new FieldMap(FIELDS)
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
        Map immutable = new FieldMap(FIELDS, mutable) // make immutable

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

    @SuppressWarnings('GroovyUnusedCatchParameter')
    @Test
    void testToMap() {
        def m = [foo: 'bar']
        jwtMap.putAll(m)
        Map returned = jwtMap.toMap()
        assertEquals 'bar', returned.foo
        //assert returned Map is mutable:
        returned.clear()
        assertEquals 0, jwtMap.size()
        assertEquals 0, returned.size()

        // now test immutable:
        jwtMap = new FieldMap(FIELDS, m)
        unsupported { jwtMap.clear() }
        //assert returned Map view reflects changes and is still immutable
        returned = jwtMap.toMap()
        assertEquals 'bar', returned.foo
        try { // assert new return value is immutable:
            returned.clear()
            fail()
        } catch(UnsupportedOperationException expected) {
        }
    }

    @Test
    void testEquals() throws Exception {
        def m1 = new FieldMap(FIELDS)
        m1.put("a", "a")

        def m2 = new FieldMap(FIELDS)
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
        def map = new FieldMap(FIELDS)
        assertEquals 'Map', map.getName()
    }

    @Test
    void testSetSecretFieldWithInvalidTypeValue() {
        def map = new FieldMap(Fields.registry(SECRET))
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
