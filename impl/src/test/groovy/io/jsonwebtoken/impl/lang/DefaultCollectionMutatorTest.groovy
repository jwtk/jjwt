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
package io.jsonwebtoken.impl.lang

import io.jsonwebtoken.Identifiable
import io.jsonwebtoken.lang.Strings
import org.junit.Before
import org.junit.Test

import static org.junit.Assert.*

/**
 * @since 0.12.0
 */
class DefaultCollectionMutatorTest {

    private int changeCount
    private DefaultCollectionMutator m

    @Before
    void setUp() {
        changeCount = 0
        m = new DefaultCollectionMutator(null) {
            @Override
            protected void changed() {
                changeCount++
            }
        }
    }

    @Test
    void newInstance() {
        def c = m.getCollection()
        assertNotNull c
        assertTrue c.isEmpty()
    }

    @Test
    void addEmpty() {
        m.add(Strings.EMPTY)
        assertTrue m.getCollection().isEmpty() // wasn't added
    }

    @Test
    void add() {
        def val = 'hello'
        m.add(val)
        assertEquals 1, changeCount
        assertEquals Collections.singleton(val), m.getCollection()
    }

    @Test
    void addDuplicateDoesNotTriggerChange() {
        m.add('hello')
        m.add('hello') //already in the set, no change should be reflected
        assertEquals 1, changeCount
    }

    @Test
    void addCollection() {
        def vals = ['hello', 'world']
        m.add(vals)
        assertEquals vals.size(), m.getCollection().size()
        assertTrue vals.containsAll(m.getCollection())
        assertTrue m.getCollection().containsAll(vals)
        def i = m.getCollection().iterator() // order retained
        assertEquals vals[0], i.next()
        assertEquals vals[1], i.next()
        assertFalse i.hasNext()
    }

    /**
     * Asserts that if a collection is added, each internal addition to the collection doesn't call changed(); instead
     * changed() is only called once after they've all been added to the collection
     */
    @Test
    void addCollectionTriggersSingleChange() {
        def c = ['hello', 'world']
        m.add(c)
        assertEquals 1, changeCount // only one change triggered, not c.size()
    }

    @Test(expected = IllegalArgumentException)
    void addIdentifiableWithNullId() {
        def e = new Identifiable() {
            @Override
            String getId() {
                return null
            }
        }
        m.add(e)
    }

    @Test(expected = IllegalArgumentException)
    void addIdentifiableWithEmptyId() {
        def e = new Identifiable() {
            @Override
            String getId() {
                return '  '
            }
        }
        m.add(e)
    }

    @Test
    void remove() {
        m.add('hello').add('world')
        m.remove('hello')
        assertEquals Collections.singleton('world'), m.getCollection()
    }

    @Test
    void removeMissingDoesNotTriggerChange() {
        m.remove('foo') // not in the collection, no change should be registered
        assertEquals 0, changeCount
    }

    @Test
    void clear() {
        m.add('one').add('two').add(['three', 'four'])
        assertEquals 4, m.getCollection().size()
        m.clear()
        assertTrue m.getCollection().isEmpty()
    }
}
