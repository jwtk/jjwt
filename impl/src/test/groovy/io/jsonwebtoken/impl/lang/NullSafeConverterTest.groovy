package io.jsonwebtoken.impl.lang

import org.junit.Test

import static org.junit.Assert.assertEquals
import static org.junit.Assert.assertNull

class NullSafeConverterTest {

    @Test
    void testNullArguments() {
        def converter = new NullSafeConverter(new UriStringConverter())
        assertNull converter.applyTo(null)
        assertNull converter.applyFrom(null)
    }

    @Test
    void testNonNullArguments() {
        def converter = new NullSafeConverter(new UriStringConverter())
        String url = 'https://github.com/jwtk/jjwt'
        URI uri = new URI(url)
        assertEquals url, converter.applyTo(uri)
        assertEquals uri, converter.applyFrom(url)
    }
}
