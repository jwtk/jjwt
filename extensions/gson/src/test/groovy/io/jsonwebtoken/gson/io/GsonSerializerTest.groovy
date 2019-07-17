package io.jsonwebtoken.io

import io.jsonwebtoken.lang.Strings
import org.junit.Test

import static org.easymock.EasyMock.*
import static org.junit.Assert.*
import com.google.gson.Gson

class GsonSerializerTest {

    @Test
    void testDefaultConstructor() {
        def serializer = new GsonSerializer()
        assertNotNull serializer.gson
    }

    @Test
    void testObjectMapperConstructor() {
        def customGSON = new Gson()
        def serializer = new GsonSerializer<>(customGSON)
        assertSame customGSON, serializer.gson
    }

    @Test(expected = IllegalArgumentException)
    void testObjectMapperConstructorWithNullArgument() {
        new GsonSerializer<>(null)
    }

    @Test
    void testByte() {
        byte[] expected = "120".getBytes(Strings.UTF_8) //ascii("x") = 120
        byte[] bytes = "x".getBytes(Strings.UTF_8)
        byte[] result = new GsonSerializer().serialize(bytes[0]) //single byte
        assertTrue Arrays.equals(expected, result)
    }

    @Test
    void testByteArray() { //expect Base64 string by default:
        byte[] bytes = "hi".getBytes(Strings.UTF_8)
        String expected = '"aGk="' as String //base64(hi) --> aGk=
        byte[] result = new GsonSerializer().serialize(bytes)
        assertEquals expected, new String(result, Strings.UTF_8)
    }

    @Test
    void testEmptyByteArray() { //expect Base64 string by default:
        byte[] bytes = new byte[0]
        byte[] result = new GsonSerializer().serialize(bytes)
        assertEquals '""', new String(result, Strings.UTF_8)
    }

    @Test
    void testChar() { //expect Base64 string by default:
        byte[] result = new GsonSerializer().serialize('h' as char)
        assertEquals "\"h\"", new String(result, Strings.UTF_8)
    }

    @Test
    void testCharArray() { //expect Base64 string by default:
        byte[] result = new GsonSerializer().serialize("hi".toCharArray())
        assertEquals "\"hi\"", new String(result, Strings.UTF_8)
    }

    @Test
    void testSerialize() {
        byte[] expected = '{"hello":"世界"}'.getBytes(Strings.UTF_8)
        byte[] result = new GsonSerializer().serialize([hello: '世界'])
        assertTrue Arrays.equals(expected, result)
    }

//THIS IS COMMENTED OUT BECAUSE GSN NEVER THROWS ANY SERIALIZATION EXCEPTION    
//    @Test
//    void testSerializeFailsWithJsonProcessingException() {
//
//        def ex = createMock(JsonProcessingException)
//
//        expect(ex.getMessage()).andReturn('foo')
//
//        def serializer = new GsonSerializer() {
//            @Override
//            protected byte[] writeValueAsBytes(Object o) throws JsonProcessingException {
//                throw ex
//            }
//        }
//
//        replay ex
//
//        try {
//            serializer.serialize([hello: 'world'])
//            fail()
//        } catch (SerializationException se) {
//            assertEquals 'Unable to serialize object: foo', se.getMessage()
//            assertSame ex, se.getCause()
//        }
//
//        verify ex
//    }
}
