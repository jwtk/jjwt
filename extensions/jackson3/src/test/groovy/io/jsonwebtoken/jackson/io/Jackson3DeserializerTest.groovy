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

import io.jsonwebtoken.io.DeserializationException
import io.jsonwebtoken.io.Deserializer
import io.jsonwebtoken.io.Encoders
import io.jsonwebtoken.jackson.io.stubs.CustomBean
import io.jsonwebtoken.lang.Maps
import org.junit.Before
import org.junit.Test
import tools.jackson.core.JacksonException
import tools.jackson.databind.ObjectMapper

import static org.junit.Assert.*

class Jackson3DeserializerTest {

    private Jackson3Deserializer deserializer

    @Before
    void setUp() {
        deserializer = new Jackson3Deserializer()
    }

    @Test
    void loadService() {
        def deserializer = ServiceLoader.load(Deserializer).iterator().next()
        assertTrue deserializer instanceof Jackson3Deserializer
    }

    @Test
    void testDefaultConstructor() {
        assertSame Jackson3Serializer.DEFAULT_OBJECT_MAPPER, deserializer.objectMapper
    }

    @Test
    void testObjectMapperConstructor() {
        def customOM = new ObjectMapper()
        deserializer = new Jackson3Deserializer<>(customOM)
        assertSame customOM, deserializer.objectMapper
    }

    @Test(expected = IllegalArgumentException)
    void testObjectMapperConstructorWithNullArgument() {
        new Jackson3Deserializer<>((ObjectMapper) null)
    }

    @Test
    void testDeserialize() {
        def reader = new StringReader('{"hello":"世界"}')
        def expected = [hello: '世界']
        def result = deserializer.deserialize(reader)
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
        def result = new Jackson3Deserializer(Maps.of("custom", CustomBean).build())
                .deserialize(new StringReader(json))
        assertEquals expected, result
    }

    /**
     * Asserts https://github.com/jwtk/jjwt/issues/877
     * @since 0.12.4
     */
    @Test
    void testStrictDuplicateDetection() {
        // 'bKey' is repeated twice:
        String json = """
             {
                "aKey":"oneValue", 
                "bKey": 15,
                "bKey": "hello"
             }
            """
        try {
            new Jackson3Deserializer<>().deserialize(new StringReader(json))
            fail()
        } catch (DeserializationException expected) {
            String causeMsg = "Duplicate Object property \"bKey\"\n at [Source: REDACTED (`StreamReadFeature.INCLUDE_SOURCE_IN_LOCATION` disabled); byte offset: #UNKNOWN]"
            String msg = "Unable to deserialize: $causeMsg"
            assertEquals msg, expected.getMessage()
            assertTrue expected.getCause() instanceof JacksonException
            assertEquals causeMsg, expected.getCause().getMessage()
        }
    }

    /**
     * Asserts https://github.com/jwtk/jjwt/issues/893
     */
    @Test
    void testIgnoreUnknownPropertiesWhenDeserializeWithCustomObject() {
        
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
                    "unknown": "unknown",
                    "nestedValue": {
                        "stringValue": "nested-value",
                        "intValue": "111",
                        "dateValue": ${currentTime + 1},
                        "shortValue": 222,
                        "longValue": 333,
                        "byteValue": 10,
                        "byteArrayValue": "${base64('bytes2')}",
                        "unknown": "unknown"
                    }
                }
            }
            """

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
        def result = new Jackson3Deserializer(Maps.of("custom", CustomBean).build())
                .deserialize(new StringReader(json))
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

        def deserializer = new Jackson3Deserializer(typeMap)
        def reader = new StringReader('{"alg":"HS256"}')
        def result = deserializer.deserialize(reader)
        assertEquals(["alg": "HS256"], result)
    }

    @Test(expected = IllegalArgumentException)
    void testNullClaimTypeMap() {
        new Jackson3Deserializer((Map) null)
    }

    @Test
    void testDeserializeFailsWithException() {

        def ex = new IOException('foo')

        deserializer = new Jackson3Deserializer() {
            @Override
            protected Object doDeserialize(Reader reader) throws Exception {
                throw ex
            }
        }
        try {
            deserializer.deserialize(new StringReader('{"hello":"世界"}'))
            fail()
        } catch (DeserializationException se) {
            String msg = 'Unable to deserialize: foo'
            assertEquals msg, se.getMessage()
            assertSame ex, se.getCause()
        }
    }

    private static String base64(String input) {
        return Encoders.BASE64.encode(input.getBytes('UTF-8'))
    }
}
