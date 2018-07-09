package io.jsonwebtoken.io.impl.orgjson

import io.jsonwebtoken.SignatureAlgorithm
import io.jsonwebtoken.codec.Encoder
import io.jsonwebtoken.io.SerializationException
import io.jsonwebtoken.lang.DateFormats
import io.jsonwebtoken.lang.Strings
import org.json.JSONObject
import org.json.JSONString
import org.junit.Before
import org.junit.Test
import static org.junit.Assert.*

class OrgJsonSerializerTest {

    private OrgJsonSerializer s

    @Before
    void setUp() {
        s = new OrgJsonSerializer()
    }

    private String ser(Object o) {
        byte[] bytes = s.serialize(o)
        return new String(bytes, Strings.UTF_8)
    }

    @Test(expected = SerializationException)
    void testInvalidArgument() {
        s.serialize(new Object())
    }

    @Test
    void testToBytesFailure() {

        final IllegalArgumentException iae = new IllegalArgumentException("foo")

        s = new OrgJsonSerializer() {
            @Override
            protected byte[] toBytes(Object o) {
                throw iae
            }
        }
        try {
            s.serialize("hello")
            fail()
        } catch (SerializationException se) {
            assertTrue se.getMessage().endsWith(iae.getMessage())
            assertSame iae, se.getCause()
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
        String encoded = Encoder.BASE64.encode(bytes)
        String expected = "\"$encoded\"" as String
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
    void testDate() {
        Date now = new Date()
        String formatted = DateFormats.formatIso8601(now)
        assertEquals "\"$formatted\"" as String, ser(now)
    }

    @Test
    void testCalendar() {
        def cal = Calendar.getInstance(TimeZone.getTimeZone("UTC"))
        def now = cal.getTime()
        String formatted = DateFormats.formatIso8601(now)
        assertEquals "\"$formatted\"" as String, ser(cal)
    }

    @Test
    void testSimpleIntArray() {
        assertEquals '[1,2]', ser( [1, 2] as int[] )
    }

    @Test
    void testIntegerArrayWithNullElements() {
        assertEquals '[1,null]', ser( [1, null] as Integer[] )
    }

    @Test
    void testIntegerList() {
        assertEquals '[1,2]', ser( [1, 2] as List)
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
        assertEquals '[1,null,null]', ser( [1, null, null] as List)
    }

    @Test
    void testListWithSingleNullElement() {
        assertEquals '[null]', ser([null] as List)
    }

    @Test
    void testListWithNestedObject() {
        assertEquals '[1,null,{"hello":"世界"}]', ser([1, null, [hello: '世界']])
    }
}
