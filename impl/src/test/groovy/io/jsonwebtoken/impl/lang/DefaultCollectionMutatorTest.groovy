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
 * @since JJWT_RELEASE_VERSION
 */
class DefaultCollectionMutatorTest {

    private DefaultCollectionMutator m

    @Before
    void setUp() {
        m = new DefaultCollectionMutator(null)
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
        assertEquals Collections.singleton(val), m.getCollection()
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
    void clear() {
        m.add('one').add('two').add(['three', 'four'])
        assertEquals 4, m.getCollection().size()
        m.clear()
        assertTrue m.getCollection().isEmpty()
    }
}
