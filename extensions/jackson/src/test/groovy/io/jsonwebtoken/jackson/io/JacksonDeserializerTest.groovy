/*
 * Copyright (C) 2014 jsonwebtoken.io
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
//file:noinspection GrDeprecatedAPIUsage
package io.jsonwebtoken.jackson.io

import com.fasterxml.jackson.databind.ObjectMapper
import io.jsonwebtoken.io.DeserializationException
import io.jsonwebtoken.io.Deserializer
import io.jsonwebtoken.io.Encoders
import io.jsonwebtoken.jackson.io.stubs.CustomBean
import io.jsonwebtoken.lang.Maps
import io.jsonwebtoken.lang.Strings
import org.junit.Before
import org.junit.Test

import static org.hamcrest.CoreMatchers.instanceOf
import static org.junit.Assert.*

class JacksonDeserializerTest {

    private JacksonDeserializer deserializer

    @Before
    void setUp() {
        deserializer = new JacksonDeserializer()
    }

    @Test
    void loadService() {
        def deserializer = ServiceLoader.load(Deserializer).iterator().next()
        assertThat(deserializer, instanceOf(JacksonDeserializer))
    }

    @Test
    void testDefaultConstructor() {
        def fields = deserializer.getClass().superclass.declaredFields as List
        def field = fields.find { it.type == ObjectMapper }
        field.accessible = true
        ObjectMapper found = field.get(deserializer) as ObjectMapper
        assertSame JacksonWriter.DEFAULT_OBJECT_MAPPER, found
    }

    @Test
    void testObjectMapperConstructor() {
        def customOM = new ObjectMapper()
        deserializer = new JacksonDeserializer(customOM)
        def fields = deserializer.getClass().superclass.declaredFields as List
        def field = fields.find { it.type == ObjectMapper }
        field.accessible = true
        ObjectMapper found = field.get(deserializer) as ObjectMapper
        assertSame customOM, found
    }

    @Test(expected = IllegalArgumentException)
    void testObjectMapperConstructorWithNullArgument() {
        new JacksonDeserializer<>((ObjectMapper) null)
    }

    @Test
    void testDeserialize() {
        byte[] serialized = '{"hello":"世界"}'.getBytes(Strings.UTF_8)
        def expected = [hello: '世界']
        def result = new JacksonDeserializer().deserialize(serialized)
        assertEquals expected, result
    }

    @Test
    void testDeserializeWithCustomObject() {

        long currentTime = System.currentTimeMillis()

        String json = """
             {
                "oneKey":"oneValue", 
                "custom": {
                    "stringValue": "s-value",
                    "intValue": "11",
                    "dateValue": ${currentTime},
                    "shortValue": 22,
                    "longValue": 33,
                    "byteValue": 15,
                    "byteArrayValue": "${base64('bytes')}",
                    "nestedValue": {
                        "stringValue": "nested-value",
                        "intValue": "111",
                        "dateValue": ${currentTime + 1},
                        "shortValue": 222,
                        "longValue": 333,
                        "byteValue": 10,
                        "byteArrayValue": "${base64('bytes2')}"
                    }
                }
            }
            """

        byte[] serialized = Strings.utf8(json)

        CustomBean expectedCustomBean = new CustomBean()
                .setByteArrayValue("bytes".getBytes("UTF-8"))
                .setByteValue(0xF as byte)
                .setDateValue(new Date(currentTime))
                .setIntValue(11)
                .setShortValue(22 as short)
                .setLongValue(33L)
                .setStringValue("s-value")
                .setNestedValue(new CustomBean()
                        .setByteArrayValue("bytes2".getBytes("UTF-8"))
                        .setByteValue(0xA as byte)
                        .setDateValue(new Date(currentTime + 1))
                        .setIntValue(111)
                        .setShortValue(222 as short)
                        .setLongValue(333L)
                        .setStringValue("nested-value")
                )

        def expected = [oneKey: "oneValue", custom: expectedCustomBean]
        def result = new JacksonDeserializer(Maps.of("custom", CustomBean).build()).deserialize(serialized)
        assertEquals expected, result
    }

    /**
     * For: https://github.com/jwtk/jjwt/issues/564
     */
    @Test
    void testMappedTypeDeserializerWithMapNullCheck() {

        // mimic map implementations that do NOT allow for null keys, or containsKey(null)
        Map typeMap = new HashMap() {
            @Override
            boolean containsKey(Object key) {
                if (key == null) {
                    throw new NullPointerException("key is null, expected for this test")
                }
                return super.containsKey(key)
            }
        }

        // TODO: the following does NOT work with Java 1.7
        // when we stop supporting that version we can use a partial mock instead
        // the `typeMap.put("custom", CustomBean)` line below results in an NPE, (only on 1.7)

//        Map typeMap = partialMockBuilder(HashMap)
//            .addMockedMethod("containsKey")
//            .createNiceMock()
//
//        expect(typeMap.containsKey(null)).andThrow(new NullPointerException("key is null, expected for this test"))
//        replay(typeMap)

        typeMap.put("custom", CustomBean)

        def deserializer = new JacksonDeserializer(typeMap)
        def result = deserializer.deserialize('{"alg":"HS256"}'.getBytes("UTF-8"))
        assertEquals(["alg": "HS256"], result)
    }

    @Test(expected = IllegalArgumentException)
    void testNullClaimTypeMap() {
        new JacksonDeserializer((Map) null)
    }

    @Test
    void testDeserializeFailsWithJsonProcessingException() {

        def ex = new IOException('foo')

        deserializer = new JacksonDeserializer() {
            @Override
            protected Object readValue(byte[] bytes) throws IOException {
                throw ex
            }
        }
        try {
            deserializer.deserialize(Strings.utf8('{"hello":"世界"}'))
            fail()
        } catch (DeserializationException se) {
            String msg = 'Unable to deserialize JSON bytes: foo'
            assertEquals msg, se.getMessage()
            assertSame ex, se.getCause()
        }
    }

    private static String base64(String input) {
        return Encoders.BASE64.encode(input.getBytes('UTF-8'))
    }
}
