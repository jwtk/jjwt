package io.jsonwebtoken.lang

import org.junit.Test

import static org.junit.Assert.*

class CollectionsTest {

    @Test
    void testAsSetFromNull() {
        assertSame java.util.Collections.emptySet(), Collections.asSet(null)
    }

    @Test
    void testAsSetFromEmpty() {
        def list = []
        assertSame java.util.Collections.emptySet(), Collections.asSet(list)
    }

    @Test
    void testAsSetFromSet() {
        def set = Collections.setOf('foo')
        assertSame set, Collections.asSet(set)
    }

    @Test
    void testAsSetFromList() {
        def list = Collections.of('one', 'two')
        def set = Collections.asSet(list)
        assertTrue set.containsAll(list)
        try {
            set.add('another')
            fail()
        } catch (UnsupportedOperationException ignored) { // expected, asSet returns immutable instances
        }
    }
}
