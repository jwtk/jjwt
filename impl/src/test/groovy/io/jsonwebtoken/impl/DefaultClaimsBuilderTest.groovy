package io.jsonwebtoken.impl

import org.junit.Before
import org.junit.Test

import static org.junit.Assert.assertEquals
import static org.junit.Assert.assertTrue

class DefaultClaimsBuilderTest {

    DefaultClaimsBuilder builder

    @Before
    void setUp() {
        this.builder = new DefaultClaimsBuilder()
    }

    @Test
    void testPut() {
        builder.put('foo', 'bar')
        assertEquals 'bar', builder.build().foo
    }

    @Test
    void testPutAll() {
        def m = [foo: 'bar', hello: 'world']
        builder.putAll(m)
        assertEquals m, builder.build()
    }

    @Test
    void testPutAllEmpty() {
        builder.putAll([:])
        assertTrue builder.build().isEmpty()
    }

    @Test
    void testPutAllNull() {
        builder.putAll(null)
        assertTrue builder.build().isEmpty()
    }

    @Test
    void testRemove() {
        builder.put('foo', 'bar')
        assertEquals 'bar', builder.build().foo
        builder.remove('foo')
        assertTrue builder.build().isEmpty()
    }

    @Test
    void testClear() {
        def m = [foo: 'bar', hello: 'world']
        builder.putAll(m)
        assertEquals m, builder.build()

        builder.clear()
        assertTrue builder.build().isEmpty()
    }
}
