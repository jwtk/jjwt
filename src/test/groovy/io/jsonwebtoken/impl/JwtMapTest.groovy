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

import org.junit.Test

import java.time.Instant
import java.time.LocalDateTime
import java.time.Month
import java.time.ZoneOffset

import static org.junit.Assert.*

class JwtMapTest {

    @Test
    void testToInstantFromNull() {
        Instant actual = JwtMap.toInstant(null, 'foo')
        assertNull actual
    }

    @Test
    void testToInstantFromInstant() {

        def now = Instant.now()

        Instant convertedInstant = JwtMap.toInstant(now, 'foo')

        assertSame convertedInstant, now

    }

    @Test
    void testToInstantFromString() {

        Instant date = LocalDateTime.of(2015, Month.JANUARY, 1, 12, 0, 0)
                .toInstant(ZoneOffset.UTC)

        Instant convertedInstant = JwtMap.toInstant(String.valueOf(date.getEpochSecond()), 'foo')

        assertEquals date, convertedInstant
    }

    @Test
    void testToInstantFromNonInstantObject() {
        try {
            JwtMap.toInstant(new Object() { @Override public String toString() {return 'hi'} }, 'foo')
            fail()
        } catch (IllegalStateException iae) {
            assertEquals iae.message, "Cannot convert 'foo' value [hi] to Instant instance."
        }
    }

    @Test
    void testContainsKey() {
        def m = new JwtMap()
        m.put('foo', 'bar')
        assertTrue m.containsKey('foo')
    }

    @Test
    void testContainsValue() {
        def m = new JwtMap()
        m.put('foo', 'bar')
        assertTrue m.containsValue('bar')
    }

    @Test
    void testRemoveByPuttingNull() {
        def m = new JwtMap()
        m.put('foo', 'bar')
        assertTrue m.containsKey('foo')
        assertTrue m.containsValue('bar')
        m.put('foo', null)
        assertFalse m.containsKey('foo')
        assertFalse m.containsValue('bar')
    }

    @Test
    void testPutAll() {
        def m = new JwtMap();
        m.putAll([a: 'b', c: 'd'])
        assertEquals m.size(), 2
        assertEquals m.a, 'b'
        assertEquals m.c, 'd'
    }

    @Test
    void testPutAllWithNullArgument() {
        def m = new JwtMap();
        m.putAll((Map)null)
        assertEquals m.size(), 0
    }

    @Test
    void testClear() {
        def m = new JwtMap();
        m.put('foo', 'bar')
        assertEquals m.size(), 1
        m.clear()
        assertEquals m.size(), 0
    }

    @Test
    void testKeySet() {
        def m = new JwtMap()
        m.putAll([a: 'b', c: 'd'])
        assertEquals( m.keySet(), ['a', 'c'] as Set)
    }

    @Test
    void testValues() {
        def m = new JwtMap()
        m.putAll([a: 'b', c: 'd'])
        def s = ['b', 'd']
        assertTrue m.values().containsAll(s) && s.containsAll(m.values())
    }

    @Test
    public void testEquals() throws Exception {
        def m1 = new JwtMap();
        m1.put("a", "a");

        def m2 = new JwtMap();
        m2.put("a", "a");

        assertEquals(m1, m2);
    }

    @Test
    public void testHashcode() throws Exception {
        def m = new JwtMap();
        def hashCodeEmpty = m.hashCode();

        m.put("a", "b");
        def hashCodeNonEmpty = m.hashCode();
        assertTrue(hashCodeEmpty != hashCodeNonEmpty);

        def identityHash = System.identityHashCode(m);
        assertTrue(hashCodeNonEmpty != identityHash);
    }
}
