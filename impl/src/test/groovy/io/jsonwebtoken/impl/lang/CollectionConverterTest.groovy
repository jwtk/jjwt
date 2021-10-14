package io.jsonwebtoken.impl.lang

import io.jsonwebtoken.io.Decoders
import io.jsonwebtoken.io.Encoders
import org.junit.Test

import java.nio.charset.StandardCharsets

import static org.junit.Assert.*

class CollectionConverterTest {

    private static final UriStringConverter ELEMENT_CONVERTER = new UriStringConverter(); //any will do

    @Test
    void testApplyToNull() {
        assertNull Converters.forSet(ELEMENT_CONVERTER).applyTo(null)
        assertNull Converters.forList(ELEMENT_CONVERTER).applyTo(null)
    }

    @Test
    void testApplyToEmpty() {
        def set = [] as Set
        assertSame set, Converters.forSet(ELEMENT_CONVERTER).applyTo(set)
        def list = [] as List
        assertSame list, Converters.forList(ELEMENT_CONVERTER).applyTo(list)
    }

    @Test
    void testApplyFromNull() {
        assertNull Converters.forSet(ELEMENT_CONVERTER).applyFrom(null)
        assertNull Converters.forList(ELEMENT_CONVERTER).applyFrom(null)
    }

    @Test
    void testApplyFromEmpty() {
        def set = Converters.forSet(ELEMENT_CONVERTER).applyFrom([] as Set)
        assertNotNull set
        assertTrue set.isEmpty()
        def list = Converters.forList(ELEMENT_CONVERTER).applyFrom([])
        assertNotNull list
        assertTrue list.isEmpty()
    }

    @Test
    void testApplyFromNonPrimitiveArray() {

        String url = 'https://github.com/jwtk/jjwt'
        URI uri = ELEMENT_CONVERTER.applyFrom(url)
        def array = [url] as String[]

        def set = Converters.forSet(ELEMENT_CONVERTER).applyFrom(array)
        assertNotNull set
        assertEquals 1, set.size()
        assertEquals uri, set.iterator().next()

        def list = Converters.forList(ELEMENT_CONVERTER).applyFrom(array)
        assertNotNull list
        assertEquals 1, list.size()
        assertEquals uri, set.iterator().next()
    }

    @Test
    void testApplyFromPrimitiveArray() {

        // ensure the primitive array is not converted to a collection.  That is,
        // a byte array of length 4 should not return a collection of size 4.  It should return a collection of size 1
        // and that element is the byte array

        Converter<String, Object> converter = new Converter<String, Object>() {
            @Override
            Object applyTo(String s) {
                return Decoders.BASE64URL.decode(s);
            }

            @Override
            String applyFrom(Object o) {
                return Encoders.BASE64URL.encode((byte[]) o);
            }
        }

        byte[] bytes = "1234".getBytes(StandardCharsets.UTF_8)
        String s = converter.applyFrom(bytes)

        def set = Converters.forSet(converter).applyFrom(bytes)
        assertNotNull set
        assertEquals 1, set.size()
        assertEquals s, set.iterator().next()

        def list = Converters.forList(converter).applyFrom(bytes)
        assertNotNull list
        assertEquals 1, list.size()
        assertEquals s, set.iterator().next()
    }
}
