package io.jsonwebtoken.io.impl.orgjson

import io.jsonwebtoken.io.DeserializationException
import io.jsonwebtoken.lang.Strings
import org.junit.Test
import static org.junit.Assert.*

class OrgJsonDeserializerTest {

    @Test(expected=IllegalArgumentException)
    void testNullArgument() {
        def d = new OrgJsonDeserializer()
        d.deserialize(null)
    }

    @Test(expected = DeserializationException)
    void testEmptyByteArray() {
        def d = new OrgJsonDeserializer()
        d.deserialize(new byte[0])
    }

    @Test(expected = DeserializationException)
    void testInvalidJson() {
        def d = new OrgJsonDeserializer()
        d.deserialize('"'.getBytes(Strings.UTF_8))
    }

    @Test
    void testLiteralNull() {
        def d = new OrgJsonDeserializer();
        def b = 'null'.getBytes(Strings.UTF_8)
        def value = d.deserialize(b)
        assertNull value
    }

    @Test
    void testLiteralTrue() {
        def d = new OrgJsonDeserializer();
        def b = 'true'.getBytes(Strings.UTF_8)
        def value = d.deserialize(b)
        assertEquals Boolean.TRUE, value
    }

    @Test
    void testLiteralFalse() {
        def d = new OrgJsonDeserializer();
        def b = 'false'.getBytes(Strings.UTF_8)
        def value = d.deserialize(b)
        assertEquals Boolean.FALSE, value
    }

    @Test
    void testLiteralInteger() {
        def d = new OrgJsonDeserializer();
        def b = '1'.getBytes(Strings.UTF_8)
        def value = d.deserialize(b)
        assert value instanceof Integer
        assertEquals 1 as Integer, value
    }

    @Test
    void testLiteralDecimal() {
        def d = new OrgJsonDeserializer();
        def b = '3.14159'.getBytes(Strings.UTF_8)
        def value = d.deserialize(b)
        assert value instanceof Double
        assertEquals 3.14159 as Double, value, 0d
    }

    @Test
    void testEmptyArray() {
        def d = new OrgJsonDeserializer();
        def b = '[]'.getBytes(Strings.UTF_8)
        def value = d.deserialize(b)
        assert value instanceof List
        assertEquals 0, value.size()
    }

    @Test
    void testSimpleArray() {
        def d = new OrgJsonDeserializer();
        def b = '[1, 2]'.getBytes(Strings.UTF_8)
        def value = d.deserialize(b)
        assert value instanceof List
        def expected = [1, 2]
        assertEquals expected, value
    }

    @Test
    void testArrayWithNullElements() {
        def d = new OrgJsonDeserializer();
        def b = '[1, null, 3]'.getBytes(Strings.UTF_8)
        def value = d.deserialize(b)
        assert value instanceof List
        def expected = [1, null, 3]
        assertEquals expected, value
    }

    @Test
    void testEmptyObject() {
        def d = new OrgJsonDeserializer();
        def b = '{}'.getBytes(Strings.UTF_8)
        def value = d.deserialize(b)
        assert value instanceof Map
        assertEquals 0, value.size()
    }

    @Test
    void testSimpleObject() {
        def d = new OrgJsonDeserializer();
        def b = '{"hello": "世界"}'.getBytes(Strings.UTF_8)
        def value = d.deserialize(b)
        assert value instanceof Map
        def expected = [hello: '世界']
        assertEquals expected, value
    }

    @Test
    void testObjectWithKeyHavingNullValue() {
        def d = new OrgJsonDeserializer();
        def b = '{"hello": "世界", "test": null}'.getBytes(Strings.UTF_8)
        def value = d.deserialize(b)
        assert value instanceof Map
        def expected = [hello: '世界', test: null]
        assertEquals expected, value
    }

    @Test
    void testObjectWithKeyHavingArrayValue() {
        def d = new OrgJsonDeserializer();
        def b = '{"hello": "世界", "test": [1, 2]}'.getBytes(Strings.UTF_8)
        def value = d.deserialize(b)
        assert value instanceof Map
        def expected = [hello: '世界', test: [1, 2]]
        assertEquals expected, value
    }

    @Test
    void testObjectWithKeyHavingObjectValue() {
        def d = new OrgJsonDeserializer();
        def b = '{"hello": "世界", "test": {"foo": "bar"}}'.getBytes(Strings.UTF_8)
        def value = d.deserialize(b)
        assert value instanceof Map
        def expected = [hello: '世界', test: [foo: 'bar']]
        assertEquals expected, value
    }
}
