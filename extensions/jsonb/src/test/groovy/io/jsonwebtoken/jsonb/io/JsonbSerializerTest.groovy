package io.jsonwebtoken.jsonb.io

import io.jsonwebtoken.io.SerializationException
import io.jsonwebtoken.io.Serializer
import io.jsonwebtoken.lang.Strings
import org.junit.Test

import javax.json.bind.JsonbBuilder
import javax.json.bind.JsonbException

import static org.easymock.EasyMock.*
import static org.hamcrest.CoreMatchers.instanceOf
import static org.hamcrest.MatcherAssert.assertThat
import static org.junit.Assert.*

class JsonbSerializerTest {

  @Test
  void loadService() {
    def serializer = ServiceLoader.load(Serializer).iterator().next()
    assertThat(serializer, instanceOf(JsonbSerializer))
  }

  @Test
  void testDefaultConstructor() {
    def serializer = new JsonbSerializer()
    assertNotNull serializer.jsonb
  }

  @Test
  void testObjectMapperConstructor() {
    def customJsonb = JsonbBuilder.create()
    def serializer = new JsonbSerializer<>(customJsonb)
    assertSame customJsonb, serializer.jsonb
  }

  @Test(expected = NullPointerException)
  void testObjectMapperConstructorWithNullArgument() {
    new JsonbSerializer<>(null)
  }

  @Test
  void testByte() {
    byte[] expected = "120".getBytes(Strings.UTF_8) //ascii("x") = 120
    byte[] bytes = "x".getBytes(Strings.UTF_8)
    byte[] result = new JsonbSerializer().serialize(bytes[0]) //single byte
    assertTrue Arrays.equals(expected, result)
  }

  @Test
  void testByteArray() { //expect Base64 string by default:
    byte[] bytes = "hi".getBytes(Strings.UTF_8)
    String expected = '"aGk="' as String //base64(hi) --> aGk=
    byte[] result = new JsonbSerializer().serialize(bytes)
    assertEquals expected, new String(result, Strings.UTF_8)
  }

  @Test
  void testEmptyByteArray() { //expect Base64 string by default:
    byte[] bytes = new byte[0]
    byte[] result = new JsonbSerializer().serialize(bytes)
    assertEquals '""', new String(result, Strings.UTF_8)
  }

  @Test
  void testChar() { //expect Base64 string by default:
    byte[] result = new JsonbSerializer().serialize('h' as char)
    assertEquals "\"h\"", new String(result, Strings.UTF_8)
  }

  @Test
  void testCharArray() { //expect Base64 string by default:
    byte[] result = new JsonbSerializer().serialize("hi".toCharArray())
    assertEquals "\"hi\"", new String(result, Strings.UTF_8)
  }

  @Test
  void testSerialize() {
    byte[] expected = '{"hello":"世界"}'.getBytes(Strings.UTF_8)
    byte[] result = new JsonbSerializer().serialize([hello: '世界'])
    assertTrue Arrays.equals(expected, result)
  }


  @Test
  void testSerializeFailsWithJsonProcessingException() {

    def ex = createMock(JsonbException)

    expect(ex.getMessage()).andReturn('foo')

    def serializer = new JsonbSerializer() {
      @Override
      protected byte[] writeValueAsBytes(Object o) throws JsonbException {
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
