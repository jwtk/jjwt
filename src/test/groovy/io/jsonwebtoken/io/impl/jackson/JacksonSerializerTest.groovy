package io.jsonwebtoken.io.impl.jackson

import com.fasterxml.jackson.core.JsonProcessingException
import com.fasterxml.jackson.databind.ObjectMapper
import io.jsonwebtoken.codec.Encoder
import io.jsonwebtoken.io.SerializationException
import io.jsonwebtoken.lang.Strings
import org.junit.Test

import static org.easymock.EasyMock.createMock
import static org.easymock.EasyMock.expect
import static org.easymock.EasyMock.replay
import static org.easymock.EasyMock.verify
import static org.junit.Assert.*

class JacksonSerializerTest {

    @Test
    void testDefaultConstructor() {
        def serializer = new JacksonSerializer()
        assertNotNull serializer.objectMapper
    }

    @Test
    void testObjectMapperConstructor() {
        def customOM = new ObjectMapper()
        def serializer = new JacksonSerializer<>(customOM)
        assertSame customOM, serializer.objectMapper
    }

    @Test(expected = IllegalArgumentException)
    void testObjectMapperConstructorWithNullArgument() {
        new JacksonSerializer<>(null)
    }

    @Test
    void testByte() {
        byte[] expected = "120".getBytes(Strings.UTF_8) //ascii("x") = 120
        byte[] bytes = "x".getBytes(Strings.UTF_8)
        byte[] result = new JacksonSerializer().serialize(bytes[0]) //single byte
        assertTrue Arrays.equals(expected, result)
    }

    @Test
    void testByteArray() { //expect Base64 string by default:
        byte[] bytes = "hi".getBytes(Strings.UTF_8)
        String encoded = Encoder.BASE64.encode(bytes)
        String expected = "\"$encoded\"" as String
        byte[] result = new JacksonSerializer().serialize(bytes)
        assertEquals expected, new String(result, Strings.UTF_8)
    }

    @Test
    void testEmptyByteArray() { //expect Base64 string by default:
        byte[] bytes = new byte[0]
        String encoded = Encoder.BASE64.encode(bytes)
        String expected = "\"$encoded\"" as String
        byte[] result = new JacksonSerializer().serialize(bytes)
        assertEquals expected, new String(result, Strings.UTF_8)
    }

    @Test
    void testChar() { //expect Base64 string by default:
        byte[] result = new JacksonSerializer().serialize('h' as char)
        assertEquals "\"h\"", new String(result, Strings.UTF_8)
    }

    @Test
    void testCharArray() { //expect Base64 string by default:
        byte[] result = new JacksonSerializer().serialize("hi".toCharArray())
        assertEquals "\"hi\"", new String(result, Strings.UTF_8)
    }

    @Test
    void testSerialize() {
        byte[] expected = '{"hello":"世界"}'.getBytes(Strings.UTF_8)
        byte[] result = new JacksonSerializer().serialize([hello: '世界'])
        assertTrue Arrays.equals(expected, result)
    }

    @Test
    void testSerializeFailsWithJsonProcessingException() {

        def ex = createMock(JsonProcessingException)

        expect(ex.getMessage()).andReturn('foo')

        def serializer = new JacksonSerializer() {
            @Override
            protected byte[] writeValueAsBytes(Object o) throws JsonProcessingException {
                throw ex
            }
        }

        replay ex

        try {
            serializer.serialize([hello: 'world'])
            fail()
        } catch (SerializationException se) {
            assertEquals 'Unable to serialize object: foo', se.getMessage()
            assertSame ex, se.getCause()
        }

        verify ex
    }
}
