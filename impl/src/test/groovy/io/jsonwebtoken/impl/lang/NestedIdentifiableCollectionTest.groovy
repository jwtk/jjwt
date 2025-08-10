package io.jsonwebtoken.impl.lang

import io.jsonwebtoken.Identifiable
import org.junit.Before
import org.junit.Test

import static org.junit.Assert.*

class NestedIdentifiableCollectionTest {

    private int changeCount
    private NestedIdentifiableCollection c

    @Before
    void setUp() {
        changeCount = 0
        c = new NestedIdentifiableCollection(this, null) {
            @Override
            protected void changed() {
                changeCount++
            }
        }
    }

    @Test
    void defaultChangedDoesNothing() {
        changeCount = 0
        c = new NestedIdentifiableCollection(this, null)
        c.changed() // no op as default, subclasses override if they need callback
        assertEquals 0, changeCount // no change occurs by default
    }

    @Test
    void newInstance() {
        def m = c.getValues()
        assertNotNull m
        assertTrue m.isEmpty()
    }

    @Test
    void addNull() {
        c.add(null)
        assertEquals 0, changeCount
        assertTrue c.getValues().isEmpty() // wasn't added
    }

    @Test
    void add() {
        def val = new TestAlg('test', this)
        c.add(val)
        assertEquals 1, changeCount
        def expected = ['test': val]
        assertEquals expected, c.getValues()
    }

    @Test
    void addEmptyCollection() {
        assertEquals 0, changeCount
        def empty = [] as List
        c.add(empty)
        assertEquals 0, changeCount
    }

    @Test
    void addCollection() {
        def val1 = new TestAlg('id1', this)
        def val2 = new TestAlg('id2', this)
        def vals = [val1, val2]
        c.add(vals)
        assertEquals vals.size(), c.getValues().size()
        assertTrue vals.containsAll(c.getValues().values())
        assertTrue c.getValues().values().containsAll(vals)
        def i = c.getValues().values().iterator() // order retained
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
        def val1 = new TestAlg('id1', this)
        def val2 = new TestAlg('id2', this)
        def vals = [val1, val2]
        this.c.add(vals)
        assertEquals 1, changeCount // only one change triggered, not c.size()
    }

    @Test
    void remove() {
        def val1 = new TestAlg('id1', this)
        def val2 = new TestAlg('id2', this)
        c.add(val1).add(val2)
        c.remove(val1)
        assertFalse(c.values.values().contains(val1))
        def expected = [val2] as Set
        assertEquals expected, c.values.values() as Set
    }

    @Test
    void removeNull() {
        c.remove(null)
        assertEquals 0, changeCount
        assertTrue c.getValues().isEmpty()
    }

    @Test
    void removeMissingDoesNotTriggerChange() {
        def val = new TestAlg('id1', this)
        c.remove(val) // not in the collection, no change should be registered
        assertEquals 0, changeCount
    }

    @Test
    void clear() {
        def val1 = new TestAlg('id1', this)
        def val2 = new TestAlg('id2', this)
        def val3 = new TestAlg('id3', this)
        def val4 = new TestAlg('id4', this)
        c.add(val1).add(val2).add([val3, val4])
        assertEquals 4, c.getValues().size()
        c.clear()
        assertTrue c.getValues().isEmpty()
    }

    @Test
    void clearWhenEmpty() {
        assertEquals 0, changeCount
        c.clear()
        assertEquals 0, changeCount
    }

    @Test(expected = IllegalArgumentException)
    void addIdentifiableWithNullId() {
        c.add(new TestAlg(null, this))
    }

    @Test(expected = IllegalArgumentException)
    void addIdentifiableWithEmptyId() {
        c.add(new TestAlg('  ', null))
    }

    @Test
    void addIdentifiableWithSameIdEvictsExisting() {
        c.add(new TestAlg('sameId', 'foo'))
        c.add(new TestAlg('sameId', 'bar'))
        assertEquals 2, changeCount
        assertEquals 1, c.getValues().size() // second 'add' should evict first
        assertEquals 'bar', ((TestAlg) c.getValues().values().toArray()[0]).obj
    }

    private class TestAlg implements Identifiable {
        String id
        Object obj

        TestAlg(String id, Object obj) {
            this.id = id
            this.obj = obj
        }

        @Override
        String getId() {
            return id
        }

        @Override
        int hashCode() {
            return id.hashCode()
        }

        @Override
        boolean equals(Object obj) {
            return obj instanceof TestAlg && id == obj.getId()
        }
    }
}
