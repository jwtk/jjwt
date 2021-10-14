package io.jsonwebtoken.impl.lang

import org.junit.Test

import static org.junit.Assert.*

class NoConverterTest {

    @Test
    void testApplyTo() {
        def converter = new NoConverter(Integer.class)
        def val = 42
        assertSame val, converter.applyTo(val)
    }

    @Test
    void testApplyFromNull() {
        def converter = new NoConverter(Integer.class)
        assertNull converter.applyFrom(null)
    }

    @Test
    void testApplyFromInvalidType() {
        def converter = new NoConverter(Integer.class)
        try {
            converter.applyFrom('hello' as String)
        } catch (IllegalArgumentException expected) {
            assertEquals 'Unsupported value type: java.lang.String', expected.getMessage()
        }
    }
}
