package io.jsonwebtoken.impl.lang

import org.junit.Test

import static org.junit.Assert.assertNull

class StringRegistryTest {

    @Test(expected = ClassCastException)
    void testGetWithoutString() {
        def registry = new StringRegistry('foo', 'id', ['one', 'two'], Functions.identity(), true)
        assertNull registry.get(1) // not a string key
    }
}
