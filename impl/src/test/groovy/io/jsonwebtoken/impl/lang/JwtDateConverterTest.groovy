package io.jsonwebtoken.impl.lang

import org.junit.Test

import static org.junit.Assert.assertNull

class JwtDateConverterTest {

    @Test
    void testApplyToNull() {
        assertNull JwtDateConverter.INSTANCE.applyTo(null)
    }

    @Test
    void testApplyFromNull() {
        assertNull JwtDateConverter.INSTANCE.applyFrom(null)
    }

    @Test
    void testToDateWithNull() {
        assertNull JwtDateConverter.toDate(null)
    }
}
