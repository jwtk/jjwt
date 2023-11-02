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
package io.jsonwebtoken.lang

import org.junit.Before
import org.junit.Test

import static org.junit.Assert.*

class CollectionsTest {
    private Enumeration<Integer> enumeration
    private Collections.EnumerationIterator<Integer> iterator

    @Before
    void setUp() {
        Vector<Integer> vector = new Vector<>()
        vector.add(1)
        vector.add(2)
        enumeration = vector.elements()
        iterator = new Collections.EnumerationIterator<>(enumeration)
    }

    @Test
    void testHasNext() {
        assertTrue(iterator.hasNext())
        iterator.next()
        assertTrue(iterator.hasNext())
        iterator.next()
        assertFalse(iterator.hasNext())
    }

    @Test
    void testNext() {
        assertEquals(1, iterator.next())
        assertEquals(2, iterator.next())
    }

    @Test
    void testRemove() {
        try {
            iterator.remove()
            fail("Expected UnsupportedOperationException")
        } catch (UnsupportedOperationException e) {
            assertEquals("Not supported", e.getMessage())
        }
    }

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

    @Test
    void testNullSafeSetWithNullArgument() {
        def set = Collections.nullSafe((Set)null)
        assertNotNull set
        assertTrue set.isEmpty()
    }

    @Test
    void testNullSafeSetWithEmptyArgument() {
        def a = new LinkedHashSet()
        def b = Collections.nullSafe(a)
        assertSame a, b
    }

    @Test
    void testNullSafeSetWithNonEmptyArgument() {
        def a = ["hello"] as Set<String>
        def b = Collections.nullSafe(a)
        assertSame a, b
    }

    @Test
    void testNullSafeCollectionWithNullArgument() {
        Collection c = Collections.nullSafe((Collection)null)
        assertNotNull c
        assertTrue c.isEmpty()
    }

    @Test
    void testNullSafeCollectionWithEmptyArgument() {
        Collection a = new LinkedHashSet() as Collection
        def b = Collections.nullSafe(a)
        assertSame a, b
    }

    @Test
    void testNullSafeCollectionWithNonEmptyArgument() {
        Collection a = ["hello"] as Collection<String>
        def b = Collections.nullSafe(a)
        assertSame a, b
    }
}
