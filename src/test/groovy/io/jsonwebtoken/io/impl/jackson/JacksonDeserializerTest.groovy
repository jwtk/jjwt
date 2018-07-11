package io.jsonwebtoken.io.impl.jackson

import com.fasterxml.jackson.databind.ObjectMapper
import io.jsonwebtoken.io.DeserializationException
import io.jsonwebtoken.lang.Strings
import org.junit.Test

import static org.easymock.EasyMock.createMock
import static org.easymock.EasyMock.expect
import static org.easymock.EasyMock.replay
import static org.easymock.EasyMock.verify
import static org.junit.Assert.*

class JacksonDeserializerTest {

    @Test
    void testDefaultConstructor() {
        def deserializer = new JacksonDeserializer()
        assertNotNull deserializer.objectMapper
    }

    @Test
    void testObjectMapperConstructor() {
        def customOM = new ObjectMapper()
        def deserializer = new JacksonDeserializer(customOM)
        assertSame customOM, deserializer.objectMapper
    }

    @Test(expected = IllegalArgumentException)
    void testObjectMapperConstructorWithNullArgument() {
        new JacksonDeserializer<>(null)
    }

    @Test
    void testDeserialize() {
        byte[] serialized = '{"hello":"世界"}'.getBytes(Strings.UTF_8)
        def expected = [hello: '世界']
        def result = new JacksonDeserializer().deserialize(serialized)
        assertEquals expected, result
    }

    @Test
    void testDeserializeFailsWithJsonProcessingException() {

        def ex = createMock(IOException)

        expect(ex.getMessage()).andReturn('foo')

        def deserializer = new JacksonDeserializer() {
            @Override
            protected Object readValue(byte[] bytes) throws IOException {
                throw ex
            }
        }

        replay ex

        try {
            deserializer.deserialize('{"hello":"世界"}'.getBytes(Strings.UTF_8))
            fail()
        } catch (DeserializationException se) {
            assertEquals 'Unable to deserialize bytes into a java.util.Map instance: foo', se.getMessage()
            assertSame ex, se.getCause()
        }

        verify ex
    }
}
