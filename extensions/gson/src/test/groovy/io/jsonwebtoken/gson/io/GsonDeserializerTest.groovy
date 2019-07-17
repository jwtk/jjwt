package io.jsonwebtoken.gson.io

import com.google.gson.Gson
import io.jsonwebtoken.io.DeserializationException
import io.jsonwebtoken.lang.Strings
import org.junit.Test

import static org.easymock.EasyMock.*
import static org.junit.Assert.*

class GsonDeserializerTest {

    @Test
    void testDefaultConstructor() {
        def deserializer = new GsonDeserializer()
        assertNotNull deserializer.gson
    }

    @Test
    void testObjectMapperConstructor() {
        def customGSON = new Gson()
        def deserializer = new GsonDeserializer(customGSON)
        assertSame customGSON, deserializer.gson
    }

    @Test(expected = IllegalArgumentException)
    void testObjectMapperConstructorWithNullArgument() {
        new GsonDeserializer<>(null)
    }

    @Test
    void testDeserialize() {
        byte[] serialized = '{"hello":"世界"}'.getBytes(Strings.UTF_8)
        def expected = [hello: '世界']
        def result = new GsonDeserializer().deserialize(serialized)
        assertEquals expected, result
    }

    @Test
    void testDeserializeFailsWithJsonProcessingException() {

        def ex = createMock(java.io.IOException)

        expect(ex.getMessage()).andReturn('foo')

        def deserializer = new GsonDeserializer() {
            @Override
            protected Object readValue(byte[] bytes) throws java.io.IOException {
                throw ex
            }
        }

        replay ex

        try {
            deserializer.deserialize('{"hello":"世界"}'.getBytes(Strings.UTF_8))
            fail()
        } catch (DeserializationException se) {
            assertEquals 'Unable to deserialize bytes into a java.lang.Object instance: foo', se.getMessage()
            assertSame ex, se.getCause()
        }

        verify ex
    }
}
