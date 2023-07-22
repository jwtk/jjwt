package io.jsonwebtoken.impl.lang


import org.junit.Before
import org.junit.Test

import static org.junit.Assert.*

class DelegatingMapTest {

    private Map<String, String> m
    private DelegatingMap dm

    @Before
    void setUp() {
        m = [a: 'b', c: 'd']
        dm = new DelegatingMap(m)
    }

    @Test
    void testSize() {
        assertEquals m.size(), dm.size()
    }

    @Test
    void testValues() {
        def values = m.values()
        assertEquals values, dm.values()
        assertTrue values.containsAll(['b', 'd'])
    }

    @Test
    void testGet() {
        assertEquals m.a, dm.a
        assertNull dm.whatever
    }

    @Test
    void testClear() {
        assertFalse dm.isEmpty()
        dm.clear() // clear out
        assertTrue m.isEmpty() // delegate should be clear too
    }

    @Test
    void testIsEmpty() {
        assertFalse dm.isEmpty()
        assertFalse m.isEmpty()

        dm.clear()

        assertTrue dm.isEmpty()
        assertTrue m.isEmpty()
    }

    @Test
    void testContainsKey() {
        assertTrue dm.containsKey('a')
        assertFalse dm.containsKey('b')
        assertTrue dm.containsKey('c')
        assertFalse dm.containsKey('d')
    }

    @Test
    void testContainsValue() {
        assertFalse dm.containsValue('a')
        assertTrue dm.containsValue('b')
        assertFalse dm.containsValue('c')
        assertTrue dm.containsValue('d')
    }

    @Test
    void testPut() {
        dm.put('e', 'f')
        assertEquals 'f', m.e
        assertEquals 3, m.size()
        assertEquals 3, dm.size()
    }

    @Test
    void testRemove() {
        dm.remove('c')
        assertEquals 1, m.size()
        assertEquals 1, dm.size()
        assertEquals 'b', m.a
        assertEquals 'b', dm.a
    }

    @Test
    void testPutAll() {
        assertEquals 2, m.size()
        assertEquals 2, dm.size()

        dm.putAll(['1': '2', '3': '4'])

        assertEquals 4, m.size()
        assertEquals 4, dm.size()

        assertTrue m.containsKey('a')
        assertTrue m.containsKey('c')
        assertTrue m.containsKey('1')
        assertTrue m.containsKey('3')
    }

    @Test
    void testKeySet() {
        def set = ['a', 'c'] as Set<String>
        assertEquals set, m.keySet()
        assertEquals set, dm.keySet()
    }

    @Test
    void testEntrySet() {
        def entrySet = dm.entrySet()
        assertEquals m.entrySet(), entrySet
    }
}
