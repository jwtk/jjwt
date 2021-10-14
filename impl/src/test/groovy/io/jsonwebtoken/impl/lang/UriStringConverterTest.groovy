package io.jsonwebtoken.impl.lang

import org.junit.Test

import static org.junit.Assert.assertEquals

class UriStringConverterTest {

    @Test
    void testApplyTo() {
        String url = 'https://github.com/jwtk/jjwt'
        URI uri = new URI(url)
        def converter = new UriStringConverter()
        assertEquals url, converter.applyTo(uri)
        assertEquals uri, converter.applyFrom(url)
    }

    @Test
    void testApplyFromWithInvalidArgument() {
        String val = '{}asdfasdfasd'
        try {
            new UriStringConverter().applyFrom(val)
        } catch (IllegalArgumentException expected) {
            String msg = "Unable to convert String value '${val}' to URI instance: Illegal character in path at index 0: ${val}"
            assertEquals msg, expected.getMessage()
        }
    }
}
