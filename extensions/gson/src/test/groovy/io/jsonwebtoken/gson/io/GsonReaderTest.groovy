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
package io.jsonwebtoken.gson.io

import com.google.gson.Gson
import io.jsonwebtoken.io.Reader
import io.jsonwebtoken.lang.Strings
import org.junit.Before
import org.junit.Test

import java.nio.charset.StandardCharsets

import static org.junit.Assert.*

class GsonReaderTest {

    static def bytesReader(byte[] bytes) {
        return new InputStreamReader(new ByteArrayInputStream(bytes), StandardCharsets.UTF_8)
    }

    private GsonReader reader

    private def read(byte[] data) {
        return reader.read(bytesReader(data))
    }

    private def read(String s) {
        return read(Strings.utf8(s))
    }

    @Before
    void setUp() {
        reader = new GsonReader()
    }

    @Test
    void loadService() {
        def reader = ServiceLoader.load(Reader).iterator().next()
        assertTrue reader instanceof GsonReader
    }

    @Test
    void testDefaultConstructor() {
        assertNotNull reader.gson
    }

    @Test
    void testGsonConstructor() {
        def customGSON = new Gson()
        def reader = new GsonReader(customGSON)
        assertSame customGSON, reader.gson
    }

    @Test(expected = IllegalArgumentException)
    void testGsonConstructorWithNullArgument() {
        new GsonReader<>(null)
    }

    @Test
    void testRead() {
        def expected = [hello: '世界']
        assertEquals expected, read('{"hello":"世界"}')
    }

    @Test
    void testReadThrows() {
        def ex = new IllegalArgumentException('foo')
        reader = new GsonReader() {
            @Override
            protected Object readValue(java.io.Reader reader) {
                throw ex
            }
        }
        try {
            read('{"hello":"世界"}')
            fail()
        } catch (IOException expected) {
            String msg = 'Unable to read JSON as a java.lang.Object instance: foo'
            assertEquals msg, expected.message
            assertSame ex, expected.cause
        }
    }
}
