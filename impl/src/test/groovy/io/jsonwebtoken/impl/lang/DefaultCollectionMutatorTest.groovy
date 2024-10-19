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
import io.jsonwebtoken.Jwts
import io.jsonwebtoken.lang.Strings
import io.jsonwebtoken.security.MacAlgorithm
import org.junit.Before
import org.junit.Test

import java.lang.reflect.Constructor

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
        m.add(new IdentifiableObject(null, null))
    }

    @Test(expected = IllegalArgumentException)
    void addIdentifiableWithEmptyId() {
        m.add(new IdentifiableObject('  ', null))
    }

    @Test
    void addIdentifiableWithSameIdEvictsExisting() {
        m.add(new IdentifiableObject('sameId', 'foo'))
        m.add(new IdentifiableObject('sameId', 'bar'))
        assertEquals 2, changeCount
        assertEquals 1, m.collection.size() // second 'add' should evict first
        assertEquals 'bar', ((IdentifiableObject) m.collection.toArray()[0]).obj
    }

    @Test
    void addSecureDigestAlgorithmWithSameIdReplacesExisting() {
        Class<?> c = Class.forName("io.jsonwebtoken.impl.security.DefaultMacAlgorithm")
        Constructor<?> ctor = c.getDeclaredConstructor(String.class, String.class, int.class)
        ctor.setAccessible(true)
        MacAlgorithm custom = (MacAlgorithm) ctor.newInstance('HS512', 'HmacSHA512', 80)

        m.add(Jwts.SIG.HS512)
        m.add(custom)
        assertEquals 2, changeCount // replace is count as one change
        assertEquals 1, m.getCollection().size() // existing is removed as part of replacement
        assertEquals 80, ((MacAlgorithm) m.getCollection().toArray()[0]).getKeyBitLength()
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
    void replace() {
        def e1 = new IdentifiableObject('sameId', 'e1')
        def e2 = new IdentifiableObject('sameId', 'e2')

        m.add(e1)
        m.replace(e1, e2)
        assertEquals 2, changeCount // replace is count as one change
        assertEquals 1, m.getCollection().size() // existing is removed as part of replacement
        assertEquals 'e2', ((IdentifiableObject) m.getCollection().toArray()[0]).obj
    }

    @Test
    void replaceSameObject() {
        m.add('hello')
        m.replace('hello', 'hello') // replace with the same object, no change should be reflected
        assertEquals 1, changeCount
    }

    @Test(expected = NoSuchElementException)
    void replaceMissing() {
        m.replace('foo', 'bar')
    }

    @Test(expected = IllegalArgumentException)
    void replaceNull() {
        m.replace('foo', null)
    }

    @Test(expected = IllegalArgumentException)
    void replaceEmpty() {
        m.replace('foo', Strings.EMPTY)
    }

    @Test
    void clear() {
        m.add('one').add('two').add(['three', 'four'])
        assertEquals 4, m.getCollection().size()
        m.clear()
        assertTrue m.getCollection().isEmpty()
    }

    private class IdentifiableObject implements Identifiable {
        String id
        Object obj

        IdentifiableObject(String id, Object obj) {
            this.id = id
            this.obj = obj
        }

        @Override
        String getId() {
            return id
        }
    }
}
