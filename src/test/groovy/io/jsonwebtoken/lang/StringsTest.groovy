package io.jsonwebtoken.lang

import org.junit.Test

import static org.junit.Assert.*

class StringsTest {

    @Test
    void testHasText() {
        assertFalse Strings.hasText(null)
        assertFalse Strings.hasText("")
        assertFalse Strings.hasText("   ")
        assertTrue Strings.hasText("  foo   ");
        assertTrue Strings.hasText("foo")
    }
}
