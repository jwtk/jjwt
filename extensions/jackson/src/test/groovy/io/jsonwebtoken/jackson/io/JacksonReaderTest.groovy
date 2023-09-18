/*
 * Copyright © 2023 jsonwebtoken.io
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
package io.jsonwebtoken.jackson.io

import com.fasterxml.jackson.databind.ObjectMapper
import io.jsonwebtoken.io.Encoders
import io.jsonwebtoken.io.IOException
import io.jsonwebtoken.io.Reader
import io.jsonwebtoken.jackson.io.stubs.CustomBean
import io.jsonwebtoken.lang.Maps
import io.jsonwebtoken.lang.Strings
import org.junit.Before
import org.junit.Test

import java.nio.charset.StandardCharsets

import static org.junit.Assert.*

class JacksonReaderTest {

    static def bytesReader(byte[] bytes) {
        return new InputStreamReader(new ByteArrayInputStream(bytes), StandardCharsets.UTF_8)
    }

    static def bytesReader(String s) {
        return bytesReader(Strings.utf8(s))
    }

    private static String base64(String input) {
        return Encoders.BASE64.encode(input.getBytes('UTF-8'))
    }

    private JacksonReader reader

    @Before
    void setUp() {
        reader = new JacksonReader()
    }

    @Test
    void loadService() {
        def reader = ServiceLoader.load(Reader).iterator().next()
        assertTrue reader instanceof JacksonReader
    }

    @Test
    void testDefaultConstructor() {
        assertSame JacksonWriter.DEFAULT_OBJECT_MAPPER, reader.objectMapper
    }

    @Test
    void testObjectMapperConstructor() {
        def customOM = new ObjectMapper()
        reader = new JacksonReader(customOM)
        assertSame customOM, reader.objectMapper
    }

    @Test(expected = IllegalArgumentException)
    void testObjectMapperConstructorWithNullArgument() {
        new JacksonReader((ObjectMapper) null)
    }

    @Test
    void testRead() {
        byte[] data = Strings.utf8('{"hello":"世界"}')
        def expected = [hello: '世界']
        def result = reader.read(bytesReader(data))
        assertEquals expected, result
    }

    @Test
    void testReadWithCustomObject() {

        long currentTime = System.currentTimeMillis()

        byte[] jsonBytes = Strings.utf8("""{
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
            """)

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
        def result = new JacksonReader(Maps.of("custom", CustomBean).build()).read(bytesReader(jsonBytes))
        assertEquals expected, result
    }

    /**
     * For: https://github.com/jwtk/jjwt/issues/564
     */
    @Test
    void testMappedTypeReaderWithMapNullCheck() {

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

        def jr = new JacksonReader(typeMap)
        String json = '{"alg":"HS256"}'
        def result = jr.read(bytesReader(json))
        assertEquals(["alg": "HS256"], result)
    }

    @Test(expected = IllegalArgumentException)
    void testNullClaimTypeMap() {
        new JacksonReader((Map) null)
    }

    @Test
    void testReadFailsWithException() {

        def ex = new IOException('foo')

        reader = new JacksonReader() {
            @Override
            Object read(java.io.Reader reader) throws IOException {
                throw ex
            }
        }

        try {
            reader.read(bytesReader('{"hello":"世界"}'))
            fail()
        } catch (IOException expected) {
            assertSame ex, expected
        }
    }
}
