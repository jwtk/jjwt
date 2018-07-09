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

import io.jsonwebtoken.lang.DateFormats
import org.junit.Test

import static org.junit.Assert.*

class JwtMapTest {

    @Test
    void testToDateFromNull() {
        Date actual = JwtMap.toDate(null, 'foo')
        assertNull actual
    }

    @Test
    void testToDateFromDate() {
        def d = new Date()
        Date date = JwtMap.toDate(d, 'foo')
        assertSame date, d
    }

    @Test
    void testToDateFromCalendar() {
        def c = Calendar.getInstance(TimeZone.getTimeZone("UTC"))
        def d = c.getTime()
        Date date = JwtMap.toDate(c, 'foo')
        assertEquals date, d
    }

    @Test
    void testToDateFromIso8601String() {
        Date d = new Date(2015, 1, 1, 12, 0, 0)
        String s = DateFormats.formatIso8601(d, false)
        Date date = JwtMap.toDate(s, 'foo')
        assertEquals date, d
    }

    @Test
    void testToDateFromInvalidIso8601String() {
        Date d = new Date(2015, 1, 1, 12, 0, 0)
        String s = d.toString()
        try {
            JwtMap.toDate(d.toString(), 'foo')
            fail()
        } catch (IllegalArgumentException iae) {
            assertEquals "'foo' value does not appear to be ISO-8601-formatted: $s" as String, iae.getMessage()
        }
    }

    @Test
    void testToDateFromIso8601MillisString() {
        long millis = System.currentTimeMillis();
        Date d = new Date(millis)
        String s = DateFormats.formatIso8601(d)
        Date date = JwtMap.toDate(s, 'foo')
        assertEquals date, d
    }

    @Test
    void testToSpecDateWithNull() {
        assertNull JwtMap.toSpecDate(null, 'exp')
    }

    @Test
    void testToSpecDateWithLong() {
        long millis = System.currentTimeMillis()
        long seconds = (millis / 1000l) as long
        Date d = new Date(seconds * 1000)
        assertEquals d, JwtMap.toSpecDate(seconds, 'exp')
    }

    @Test
    void testToSpecDateWithString() {
        Date d = new Date(2015, 1, 1, 12, 0, 0)
        String s = (d.getTime() / 1000) + '' //JWT timestamps are in seconds - need to strip millis
        Date date = JwtMap.toSpecDate(s, 'exp')
        assertEquals date, d
    }

    @Test
    void testToSpecDateWithIso8601String() {
        long millis = System.currentTimeMillis();
        Date d = new Date(millis)
        String s = DateFormats.formatIso8601(d)
        Date date = JwtMap.toSpecDate(s, 'exp')
        assertEquals date, d
    }

    @Test
    void testToSpecDateWithDate() {
        long millis = System.currentTimeMillis();
        Date d = new Date(millis)
        Date date = JwtMap.toSpecDate(d, 'exp')
        assertSame d, date
    }

    @Deprecated //remove just before 1.0.0
    @Test
    void testSetDate() {
        def m = new JwtMap()
        m.put('foo', 'bar')
        m.setDate('foo', null)
        assertNull m.get('foo')
        long millis = System.currentTimeMillis()
        long seconds = (millis / 1000l) as long
        Date date = new Date(millis)
        m.setDate('foo', date)
        assertEquals seconds, m.get('foo')
    }

    @Test
    void testToDateFromNonDateObject() {
        try {
            JwtMap.toDate(new Object() { @Override public String toString() {return 'hi'} }, 'foo')
            fail()
        } catch (IllegalStateException iae) {
            assertEquals iae.message, "Cannot create Date from 'foo' value 'hi'."
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
    void testEquals() throws Exception {
        def m1 = new JwtMap();
        m1.put("a", "a");

        def m2 = new JwtMap();
        m2.put("a", "a");

        assertEquals(m1, m2);
    }

    @Test
    void testHashcode() throws Exception {
        def m = new JwtMap();
        def hashCodeEmpty = m.hashCode();

        m.put("a", "b");
        def hashCodeNonEmpty = m.hashCode();
        assertTrue(hashCodeEmpty != hashCodeNonEmpty);

        def identityHash = System.identityHashCode(m);
        assertTrue(hashCodeNonEmpty != identityHash);
    }
}
