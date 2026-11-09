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
package io.jsonwebtoken.jackson.testkit

import io.jsonwebtoken.io.Serializer
import io.jsonwebtoken.lang.Strings
import io.jsonwebtoken.security.ConfidentialValue
import org.junit.Before
import org.junit.Test

import static org.junit.Assert.*

/**
 * Test cases that every JJWT Jackson {@link Serializer} must pass, regardless of which Jackson generation it is
 * built on.  Each Jackson extension module extends this class and only supplies the handful of factory methods
 * below, guaranteeing all modules are held to exactly the same assertions.
 */
abstract class AbstractJacksonSerializerTest {

    protected Serializer ser

    protected abstract Serializer newSerializer()

    protected abstract Serializer newSerializer(Object objectMapper)

    protected abstract Object newObjectMapper()

    protected abstract Object defaultObjectMapper()

    @Before
    void setUp() {
        ser = newSerializer()
    }

    protected byte[] serialize(def value) {
        def os = new ByteArrayOutputStream()
        ser.serialize(value, os)
        return os.toByteArray()
    }

    protected String json(def value) {
        return Strings.utf8(serialize(value))
    }

    @Test
    void loadService() {
        def serializer = ServiceLoader.load(Serializer).iterator().next()
        assertSame ser.getClass(), serializer.getClass()
    }

    @Test
    void testDefaultConstructor() {
        assertSame defaultObjectMapper(), ser.objectMapper
    }

    @Test(expected = IllegalArgumentException)
    void testObjectMapperConstructorWithNullArgument() {
        newSerializer(null)
    }

    @Test
    void testObjectMapperConstructorAppliesJjwtModule() {
        ser = newSerializer(newObjectMapper())
        def value = new ConfidentialValue() {
            @Override
            Object get() {
                return 'hello'
            }
        }
        assertEquals '{"secret":"hello"}', json([secret: value])
    }

    @Test
    void testSerialize() {
        byte[] expected = '{"hello":"世界"}'.getBytes(Strings.UTF_8)
        byte[] result = ser.serialize([hello: '世界'])
        assertTrue Arrays.equals(expected, result)
    }

    @Test
    void testByte() {
        byte[] expected = Strings.utf8("120") //ascii("x") = 120
        byte[] bytes = Strings.utf8("x")
        assertArrayEquals expected, serialize(bytes[0]) // single byte
    }

    @Test
    void testByteArray() { //expect Base64 string by default:
        byte[] bytes = Strings.utf8("hi")
        String expected = '"aGk="' as String //base64(hi) --> aGk=
        assertEquals expected, Strings.utf8(serialize(bytes))
    }

    @Test
    void testEmptyByteArray() { //expect Base64 string by default:
        byte[] bytes = new byte[0]
        byte[] result = serialize(bytes)
        assertEquals '""', Strings.utf8(result)
    }

    @Test
    void testChar() { //expect Base64 string by default:
        byte[] result = serialize('h' as char)
        assertEquals "\"h\"", Strings.utf8(result)
    }

    @Test
    void testCharArray() { //expect Base64 string by default:
        byte[] result = serialize('hi'.toCharArray())
        assertEquals "\"hi\"", Strings.utf8(result)
    }

    @Test
    void testWriteObject() {
        byte[] expected = Strings.utf8('{"hello":"世界"}' as String)
        byte[] result = serialize([hello: '世界'])
        assertArrayEquals expected, result
    }

    @Test
    void testTypicalClaims() {
        def claims = [iss: 'https://issuer.example.com/realms/a', sub: 'joe', aud: ['a', 'b'], exp: 1700000000L,
                      admin: true, nil: null, nested: [k: [1, [x: 'y']]]]
        String expected = '{"iss":"https://issuer.example.com/realms/a","sub":"joe","aud":["a","b"],' +
                '"exp":1700000000,"admin":true,"nil":null,"nested":{"k":[1,{"x":"y"}]}}'
        assertEquals expected, json(claims)
    }

    @Test
    void testDateIsWrittenAsEpochMillis() {
        assertEquals '{"d":1700000000123}', json([d: new Date(1700000000123L)])
    }

    @Test
    void testCalendarIsWrittenAsEpochMillis() {
        def cal = Calendar.getInstance(TimeZone.getTimeZone('UTC'))
        cal.setTimeInMillis(1700000000123L)
        assertEquals '{"c":1700000000123}', json([c: cal])
    }

    @Test
    void testEnumIsWrittenByName() {
        assertEquals '{"e":"RED"}', json([e: TestEnum.RED])
    }

    @Test
    void testSupplementaryCharactersAreEscaped() {
        String grinningFace = new String(Character.toChars(0x1F600)) // outside the Basic Multilingual Plane
        String bs = (char) 92 // a single backslash, spelled this way so this source never contains a unicode escape
        // i.e. the two UTF-16 surrogates written as two six-character JSON escapes, not as raw 4-byte UTF-8:
        assertEquals '{"e":"' + bs + 'uD83D' + bs + 'uDE00"}', json([e: grinningFace])
    }

    @Test
    void testForwardSlashAndHtmlCharactersAreNotEscaped() {
        assertEquals '{"u":"a/b","h":"<a href=\'x\'>&</a>"}', json([u: 'a/b', h: "<a href='x'>&</a>"])
    }
}
