package io.jsonwebtoken.jsonb.io

import io.jsonwebtoken.io.DeserializationException
import io.jsonwebtoken.io.Deserializer
import io.jsonwebtoken.lang.Strings
import org.junit.Test

import javax.json.bind.JsonbBuilder

import static org.easymock.EasyMock.*
import static org.hamcrest.CoreMatchers.instanceOf
import static org.hamcrest.MatcherAssert.assertThat
import static org.junit.Assert.*

class JsonbDeserializerTest {

  @Test
  void loadService() {
    def deserializer = ServiceLoader.load(Deserializer).iterator().next()
    assertThat(deserializer, instanceOf(JsonbDeserializer))
  }


  @Test
  void testDefaultConstructor() {
    def deserializer = new JsonbDeserializer()
    assertNotNull deserializer.jsonb
  }

  @Test
  void testObjectMapperConstructor() {
    def customJsonb = JsonbBuilder.create()
    def deserializer = new JsonbDeserializer(customJsonb)
    assertSame customJsonb, deserializer.jsonb
  }

  @Test(expected = NullPointerException)
  void testObjectMapperConstructorWithNullArgument() {
    new JsonbDeserializer<>(null)
  }

  @Test
  void testDeserialize() {
    byte[] serialized = '{"hello":"世界"}'.getBytes(Strings.UTF_8)
    def expected = [hello: '世界']
    def result = new JsonbDeserializer().deserialize(serialized)
    assertEquals expected, result
  }

  @Test
  void testDeserializeFailsWithJsonProcessingException() {

    def ex = createMock javax.json.bind.JsonbException

    expect(ex.getMessage()).andReturn('foo')

    def deserializer = new JsonbDeserializer() {
      @Override
      protected Object readValue(byte[] bytes) throws javax.json.bind.JsonbException {
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
