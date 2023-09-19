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
import io.jsonwebtoken.io.IOException
import io.jsonwebtoken.io.Writer
import io.jsonwebtoken.lang.Strings
import org.junit.Before
import org.junit.Test

import static org.easymock.EasyMock.*
import static org.junit.Assert.*

class JacksonWriterTest {

    private JacksonWriter writer

    @Before
    void setUp() {
        writer = new JacksonWriter()
    }

    @Test
    void loadService() {
        def writer = ServiceLoader.load(Writer).iterator().next()
        assertTrue writer instanceof JacksonWriter
    }

    @Test
    void testDefaultConstructor() {
        assertSame JacksonWriter.DEFAULT_OBJECT_MAPPER, writer.objectMapper
    }

    @Test
    void testObjectMapperConstructor() {
        def customOM = new ObjectMapper()
        writer = new JacksonWriter(customOM)
        assertSame customOM, writer.objectMapper
    }

    @Test(expected = IllegalArgumentException)
    void testObjectMapperConstructorWithNullArgument() {
        new JacksonWriter(null)
    }

    @Test
    void testObjectMapperConstructorAutoRegistersModule() {
        ObjectMapper om = createMock(ObjectMapper)
        expect(om.registerModule(same(JacksonWriter.MODULE))).andReturn(om)
        replay om
        //noinspection GroovyResultOfObjectAllocationIgnored
        new JacksonWriter(om)
        verify om
    }

    byte[] write(def value) {
        def os = new ByteArrayOutputStream()
        def osw = new OutputStreamWriter(os)
        writer.write(osw, value)
        osw.close()
        return os.toByteArray()
    }

    @Test
    void testByte() {
        byte[] expected = Strings.utf8("120") //ascii("x") = 120
        byte[] bytes = Strings.utf8("x")
        assertArrayEquals expected, write(bytes[0]) // single byte
    }

    @Test
    void testByteArray() { //expect Base64 string by default:
        byte[] bytes = Strings.utf8("hi")
        String expected = '"aGk="' as String //base64(hi) --> aGk=
        assertEquals expected, Strings.utf8(write(bytes))
    }

    @Test
    void testEmptyByteArray() { //expect Base64 string by default:
        byte[] bytes = new byte[0]
        byte[] result = write(bytes)
        assertEquals '""', Strings.utf8(result)
    }

    @Test
    void testChar() { //expect Base64 string by default:
        byte[] result = write('h' as char)
        assertEquals "\"h\"", Strings.utf8(result)
    }

    @Test
    void testCharArray() { //expect Base64 string by default:
        byte[] result = write('hi'.toCharArray())
        assertEquals "\"hi\"", Strings.utf8(result)
    }

    @Test
    void testWriteObject() {
        byte[] expected = Strings.utf8('{"hello":"世界"}' as String)
        byte[] result = write([hello: '世界'])
        assertArrayEquals expected, result
    }

    @Test
    void testWriteFailsWithJsonProcessingException() {

        def ex = new IOException('foo')

        writer = new JacksonWriter() {
            @Override
            protected void writeValue(Object o, java.io.Writer writer) throws java.io.IOException {
                throw ex
            }
        }
        try {
            write([hello: 'world'])
            fail()
        } catch (IOException expected) {
            assertSame ex, expected
        }
    }
}
