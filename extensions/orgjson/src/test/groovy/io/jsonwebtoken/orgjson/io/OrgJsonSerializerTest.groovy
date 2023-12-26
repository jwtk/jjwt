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
package io.jsonwebtoken.orgjson.io

import io.jsonwebtoken.SignatureAlgorithm
import io.jsonwebtoken.io.SerializationException
import io.jsonwebtoken.io.Serializer
import io.jsonwebtoken.lang.DateFormats
import io.jsonwebtoken.lang.Strings
import io.jsonwebtoken.lang.Supplier
import org.json.JSONObject
import org.json.JSONString
import org.junit.Before
import org.junit.Test

import java.time.Instant

import static org.junit.Assert.*

class OrgJsonSerializerTest {

    private OrgJsonSerializer s

    @Before
    void setUp() {
        s = new OrgJsonSerializer()
    }

    private String ser(Object o) {
        return Strings.utf8(s.serialize(o))
    }

    @Test
    void loadService() {
        def serializer = ServiceLoader.load(Serializer).iterator().next()
        assertTrue serializer instanceof OrgJsonSerializer
    }

    @Test
    void testInvalidArgument() {
        try {
            ser(new Object())
            fail()
        } catch (SerializationException expected) {
            String causeMsg = 'Unable to serialize object of type java.lang.Object to JSON using known heuristics.'
            String msg = "Unable to serialize object of type java.lang.Object: $causeMsg"
            assertEquals msg, expected.message
        }
    }

    @Test
    void testNull() {
        assertEquals 'null', ser(null)
    }

    @Test
    void testJSONObjectNull() {
        assertEquals 'null', ser(JSONObject.NULL)
    }

    @Test
    void testJSONString() {
        def jsonString = new JSONString() {
            @Override
            String toJSONString() {
                return '"foo"'
            }
        }
        assertEquals '"foo"', ser(jsonString)
    }

    @Test
    void testTrue() {
        assertEquals 'true', ser(Boolean.TRUE)
    }

    @Test
    void testFalse() {
        assertEquals 'false', ser(Boolean.FALSE)
    }

    @Test
    void testByte() {
        assertEquals '120', ser("x".getBytes(Strings.UTF_8)[0]) //ascii("x") == 120
    }

    @Test
    void testByteArray() { //expect Base64 string by default:
        byte[] bytes = "hi".getBytes(Strings.UTF_8)
        String expected = '"aGk="' as String //base64(hi) --> aGk=
        assertEquals expected, ser(bytes)
    }

    @Test
    void testEmptyByteArray() { //base64 --> zero bytes == zero-length string:
        assertEquals "\"\"", ser(new byte[0])
    }

    @Test
    void testChar() {
        assertEquals "\"h\"", ser('h' as char)
    }

    @Test
    void testCharArray() {
        assertEquals "\"hi\"", ser("hi".toCharArray())
    }

    @Test
    void testEmptyCharArray() { //no chars == empty string:
        assertEquals "\"\"", ser(new char[0])
    }

    @Test
    void testShort() {
        assertEquals '8', ser(8 as short)
    }

    @Test
    void testInteger() {
        assertEquals '1', ser(1 as Integer)
    }

    @Test
    void testLong() {
        assertEquals '42', ser(42 as Long)
    }

    @Test
    void testBigInteger() {
        assertEquals '42', ser(BigInteger.valueOf(42 as Long))
    }

    @Test
    void testFloat() {
        assertEquals '3.14159', ser(3.14159 as Float)
    }

    @Test
    void testDouble() {
        assertEquals '3.14159', ser(3.14159 as Double)
    }

    @Test
    void testBigDecimal() {
        assertEquals '3.14159', ser(BigDecimal.valueOf(3.14159 as Double))
    }

    @Test
    void testEnum() {
        assertEquals '"HS256"', ser(SignatureAlgorithm.HS256)
    }

    @Test
    void testSupplier() {
        def supplier = new Supplier() {
            @Override
            Object get() {
                return 'test'
            }
        }
        assertEquals '"test"', ser(supplier)
    }

    @Test
    void testEmptyString() {
        assertEquals '""', ser('')
    }

    @Test
    void testWhitespaceString() {
        String value = " \n\r\t "
        assertEquals '" \\n\\r\\t "' as String, ser(value)
    }

    @Test
    void testSimpleString() {
        assertEquals '"hello 世界"', ser('hello 世界')
    }

    @Test
    void testInstant() {
        Instant instant = Instant.now()
        String formatted = DateFormats.formatIso8601(instant)
        assertEquals "\"$formatted\"" as String, ser(instant)
    }

    @Test
    void testDate() {
        Date date = new Date()
        def now = date.toInstant()
        String formatted = DateFormats.formatIso8601(now)
        assertEquals "\"$formatted\"" as String, ser(date)
    }

    @Test
    void testSimpleIntArray() {
        assertEquals '[1,2]', ser([1, 2] as int[])
    }

    @Test
    void testIntegerArrayWithNullElements() {
        assertEquals '[1,null]', ser([1, null] as Integer[])
    }

    @Test
    void testIntegerList() {
        assertEquals '[1,2]', ser([1, 2] as List)
    }

    @Test
    void testEmptyObject() {
        assertEquals '{}', ser([:])
    }

    @Test
    void testSimpleObject() {
        assertEquals '{"hello":"世界"}', ser([hello: '世界'])
    }

    @Test
    void testObjectWithKeyHavingNullValue() {
        //depending on the test platform, and that JSON doesn't require members to be ordered, either of the
        //two strings are fine (they're the same data, just the member order is different):
        String acceptable1 = '{"hello":"世界","test":null}'
        String acceptable2 = '{"test":null,"hello":"世界"}'
        String result = ser([test: null, hello: '世界'])
        assertTrue acceptable1.equals(result) || acceptable2.equals(result)
    }

    @Test
    void testObjectWithKeyHavingArrayValue() {
        //depending on the test platform, and that JSON doesn't require members to be ordered, either of the
        //two strings are fine (they're the same data, just the member order is different):
        String acceptable1 = '{"test":[1,2],"hello":"世界"}'
        String acceptable2 = '{"hello":"世界","test":[1,2]}'
        String result = ser([test: [1, 2], hello: '世界'])
        assertTrue acceptable1.equals(result) || acceptable2.equals(result)
    }

    @Test
    void testObjectWithKeyHavingObjectValue() {
        //depending on the test platform, and that JSON doesn't require members to be ordered, either of the
        //two strings are fine (they're the same data, just the member order is different):
        String acceptable1 = '{"test":{"foo":"bar"},"hello":"世界"}'
        String acceptable2 = '{"hello":"世界","test":{"foo":"bar"}}'
        String result = ser([test: [foo: 'bar'], hello: '世界'])
        assertTrue acceptable1.equals(result) || acceptable2.equals(result)
    }

    @Test
    void testListWithNullElements() {
        assertEquals '[1,null,null]', ser([1, null, null] as List)
    }

    @Test
    void testListWithSingleNullElement() {
        assertEquals '[null]', ser([null] as List)
    }

    @Test
    void testListWithNestedObject() {
        assertEquals '[1,null,{"hello":"世界"}]', ser([1, null, [hello: '世界']])
    }

    @Test
    void testSerialize() {
        assertEquals '"hello"', ser('hello')
    }

    @Test
    void testIOExceptionConvertedToSerializationException() {
        try {
            ser(new Object())
            fail()
        } catch (SerializationException expected) {
            String causeMsg = 'Unable to serialize object of type java.lang.Object to JSON using known heuristics.'
            String msg = "Unable to serialize object of type java.lang.Object: $causeMsg"
            assertEquals causeMsg, expected.cause.message
            assertEquals msg, expected.message
        }
    }

    @Test
    void testToBytes() {
        assertEquals 'null', Strings.utf8(s.toBytes(null))
        assertEquals '"hello"', Strings.utf8(s.toBytes('hello'))
    }
}
