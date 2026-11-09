/*
 * Copyright © 2026 jsonwebtoken.io
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
package io.jsonwebtoken.jackson.testkit

import io.jsonwebtoken.io.DeserializationException
import io.jsonwebtoken.io.Deserializer
import io.jsonwebtoken.io.Encoders
import io.jsonwebtoken.lang.Maps
import org.junit.Before
import org.junit.Test

import static org.junit.Assert.*

/**
 * Test cases that every JJWT Jackson {@link Deserializer} must pass, regardless of which Jackson generation it is
 * built on.  Each Jackson extension module extends this class and only supplies the handful of factory methods
 * below, guaranteeing all modules are held to exactly the same assertions.
 */
abstract class AbstractJacksonDeserializerTest {

    protected Deserializer deserializer

    protected abstract Deserializer newDeserializer()

    protected abstract Deserializer newDeserializer(Object objectMapper)

    protected abstract Deserializer newDeserializer(Map<String, Class<?>> claimTypeMap)

    protected abstract Deserializer newDeserializer(Object objectMapper, Map<String, Class<?>> claimTypeMap)

    protected abstract Deserializer newFailingDeserializer(Exception e)

    protected abstract Object newObjectMapper()

    protected abstract Object defaultObjectMapper()

    protected abstract Class<? extends Throwable> duplicateMemberExceptionType()

    protected abstract String duplicateMemberMessage(String memberName)

    protected abstract String duplicateMemberLocation(int line, int column)

    @Before
    void setUp() {
        deserializer = newDeserializer()
    }

    protected static String base64(String input) {
        return Encoders.BASE64.encode(input.getBytes('UTF-8'))
    }

    protected def read(String json) {
        return deserializer.deserialize(new StringReader(json))
    }

    @Test
    void loadService() {
        def deserializer = ServiceLoader.load(Deserializer).iterator().next()
        assertSame this.deserializer.getClass(), deserializer.getClass()
    }

    @Test
    void testDefaultConstructor() {
        assertSame defaultObjectMapper(), deserializer.objectMapper
    }

    @Test
    void testObjectMapperConstructor() {
        def customOM = newObjectMapper()
        deserializer = newDeserializer(customOM)
        assertSame customOM, deserializer.objectMapper
    }

    @Test(expected = IllegalArgumentException)
    void testObjectMapperConstructorWithNullArgument() {
        newDeserializer((Object) null)
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
        def result = newDeserializer(Maps.of("custom", CustomBean).build())
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
            read(json)
            fail()
        } catch (DeserializationException expected) {
            String causeMsg = duplicateMemberMessage('bKey') + "\n at [Source: REDACTED (`StreamReadFeature.INCLUDE_SOURCE_IN_LOCATION` disabled); ${duplicateMemberLocation(5, 23)}]"
            String msg = "Unable to deserialize: $causeMsg"
            assertEquals msg, expected.getMessage()
            assertTrue duplicateMemberExceptionType().isInstance(expected.getCause())
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
        def result = newDeserializer(Maps.of("custom", CustomBean).build())
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

        typeMap.put("custom", CustomBean)

        def deserializer = newDeserializer(typeMap)
        def reader = new StringReader('{"alg":"HS256"}')
        def result = deserializer.deserialize(reader)
        assertEquals(["alg": "HS256"], result)
    }

    @Test(expected = IllegalArgumentException)
    void testNullClaimTypeMap() {
        newDeserializer((Map) null)
    }

    @Test
    void testDeserializeFailsWithException() {

        def ex = new IOException('foo')

        deserializer = newFailingDeserializer(ex)
        try {
            deserializer.deserialize(new StringReader('{"hello":"世界"}'))
            fail()
        } catch (DeserializationException se) {
            String msg = 'Unable to deserialize: foo'
            assertEquals msg, se.getMessage()
            assertSame ex, se.getCause()
        }
    }

    @Test
    void testObjectMapperAndClaimTypeMapConstructor() {
        def deserializer = newDeserializer(newObjectMapper(), Maps.of("custom", CustomBean).build())
        def result = deserializer.deserialize(new StringReader('{"custom":{"stringValue":"s"},"other":{"stringValue":"s"}}'))
        assertEquals new CustomBean().setStringValue('s').getStringValue(), result.custom.getStringValue()
        assertTrue result.custom instanceof CustomBean
        assertEquals([stringValue: 's'], result.other) // unmapped claims remain Maps
    }

    @Test(expected = IllegalArgumentException)
    void testObjectMapperAndClaimTypeMapConstructorWithNullObjectMapper() {
        newDeserializer((Object) null, Maps.of("custom", CustomBean).build())
    }

    @Test(expected = IllegalArgumentException)
    void testObjectMapperAndClaimTypeMapConstructorWithNullClaimTypeMap() {
        newDeserializer(newObjectMapper(), (Map) null)
    }

    @Test
    void testUntypedNumbers() {
        def result = read('{"i":1,"l":2147483648,"bi":123456789012345678901234567890,"d":1.5}')
        assertEquals Integer, result.i.getClass()
        assertEquals Long, result.l.getClass()
        assertEquals BigInteger, result.bi.getClass()
        assertEquals Double, result.d.getClass()
    }

    @Test
    void testUntypedStructures() {
        def result = read('{"a":[1,"x",null,{"b":true}],"u":"https:\\/\\/a\\/b"}')
        assertEquals([a: [1, 'x', null, [b: true]], u: 'https://a/b'], result)
        assertTrue result instanceof LinkedHashMap
        assertTrue result.a instanceof ArrayList
    }

    @Test
    void testNestedDuplicateDetection() {
        try {
            read('{"a":{"b":1,"b":2}}')
            fail()
        } catch (DeserializationException expected) {
            assertTrue duplicateMemberExceptionType().isInstance(expected.getCause())
            assertTrue expected.getMessage().startsWith('Unable to deserialize: ' + duplicateMemberMessage('b'))
        }
    }

    @Test
    void testTrailingContentIsIgnored() {
        assertEquals([a: 1], read('{"a":1}{"b":2}'))
        assertEquals([a: 1], read('{"a":1} x'))
    }

    @Test
    void testNonStandardJsonIsRejected() {
        for (String json : ["{'a':1}", '{a:1}', '{/*c*/"a":1}', '{"a":1,}', '{"a":01}', '{"a":NaN}', '']) {
            try {
                read(json)
                fail("Should have been rejected: $json")
            } catch (DeserializationException expected) {
            }
        }
    }

    @Test
    void testCustomObjectNullForPrimitiveUsesDefaultValue() {
        def result = newDeserializer(Maps.of("custom", CustomBean).build())
                .deserialize(new StringReader('{"custom":{"intValue":null,"stringValue":"s"}}'))
        assertEquals 0, result.custom.getIntValue()
        assertEquals 's', result.custom.getStringValue()
    }

    @Test
    void testCustomObjectCollectionPropertyWithoutSetter() {
        def result = newDeserializer(Maps.of("custom", SetterlessBean).build())
                .deserialize(new StringReader('{"custom":{"items":["a","b"]}}'))
        assertEquals(['a', 'b'], result.custom.getItems())
    }

    @Test
    void testCustomEnumIsReadByName() {
        def result = newDeserializer(Maps.of("custom", TestEnum).build())
                .deserialize(new StringReader('{"custom":"RED"}'))
        assertSame TestEnum.RED, result.custom
    }
}
