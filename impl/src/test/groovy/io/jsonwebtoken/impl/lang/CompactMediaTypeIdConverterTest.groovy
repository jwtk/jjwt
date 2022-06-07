package io.jsonwebtoken.impl.lang

import org.junit.Test

import static org.junit.Assert.assertEquals

class CompactMediaTypeIdConverterTest {

    private static final Converter<String, Object> converter = CompactMediaTypeIdConverter.INSTANCE

    @Test(expected = IllegalArgumentException)
    void testApplyToNull() {
        converter.applyTo(null)
    }

    @Test(expected = IllegalArgumentException)
    void testApplyToEmpty() {
        converter.applyTo('')
    }

    @Test(expected = IllegalArgumentException)
    void testApplyToBlank() {
        converter.applyTo('    ')
    }

    @Test(expected = IllegalArgumentException)
    void testApplyFromNull() {
        converter.applyFrom(null)
    }

    @Test(expected = IllegalArgumentException)
    void testApplyFromNonString() {
        converter.applyFrom(42)
    }

    @Test
    void testNonApplicationMediaType() {
        String cty = 'foo'
        assertEquals cty, converter.applyTo(cty)
        assertEquals cty, converter.applyFrom(cty)
    }

    @Test
    void testApplicationMediaType() {
        String cty = 'foo'
        String mediaType = "application/$cty"
        // assert it has been automatically compacted per https://datatracker.ietf.org/doc/html/rfc7515#section-4.1.10 :
        assertEquals cty, converter.applyTo(mediaType)
    }

    @Test
    void testCaseInsensitiveApplicationMediaType() { // media type values are case insensitive
        String cty = 'FoO'
        String mediaType = "aPpLiCaTiOn/$cty"
        // assert it has been automatically compacted per https://datatracker.ietf.org/doc/html/rfc7515#section-4.1.10 :
        assertEquals cty, converter.applyTo(mediaType)
    }

    @Test
    void testApplicationMediaTypeWithMoreThanOneForwardSlash() {
        String mediaType = "application/foo;part=1/2"
        // cannot be compacted per https://datatracker.ietf.org/doc/html/rfc7515#section-4.1.10 :
        assertEquals mediaType, converter.applyTo(mediaType)
    }

    @Test
    void testCaseInsensitiveApplicationMediaTypeWithMoreThanOneForwardSlash() {
        String mediaType = "aPpLiCaTiOn/foo;part=1/2"
        // cannot be compacted per https://datatracker.ietf.org/doc/html/rfc7515#section-4.1.10 :
        assertEquals mediaType, converter.applyTo(mediaType)
    }

    @Test
    void testApplicationMediaTypeWithMoreThanOneForwardSlash2() {
        String mediaType = "application//test"
        // cannot be compacted per https://datatracker.ietf.org/doc/html/rfc7515#section-4.1.10 :
        assertEquals mediaType, converter.applyTo(mediaType)
    }
}
