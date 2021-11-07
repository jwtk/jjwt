package io.jsonwebtoken.impl.lang

import org.junit.Test

import static org.junit.Assert.*

/**
 * @since JJWT_RELEASE_VERSION
 */
class RequiredTypeConverterTest {

    @Test
    void testApplyTo() {
        def converter = new RequiredTypeConverter(Integer.class)
        def val = 42
        assertSame val, converter.applyTo(val)
    }

    @Test
    void testApplyFromNull() {
        def converter = new RequiredTypeConverter(Integer.class)
        assertNull converter.applyFrom(null)
    }

    @Test
    void testApplyFromInvalidType() {
        def converter = new RequiredTypeConverter(Integer.class)
        try {
            converter.applyFrom('hello' as String)
        } catch (IllegalArgumentException expected) {
            String msg = 'Unsupported value type. Expected: java.lang.Integer, found: java.lang.String'
            assertEquals msg, expected.getMessage()
        }
    }
}
