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

import io.jsonwebtoken.io.DeserializationException
import io.jsonwebtoken.io.Deserializer
import io.jsonwebtoken.lang.Strings
import org.junit.Before
import org.junit.Test

import static org.junit.Assert.assertEquals
import static org.junit.Assert.fail

class OrgJsonDeserializerTest {

    private OrgJsonDeserializer deserializer

    @Before
    void setUp() {
        deserializer = new OrgJsonDeserializer()
    }

    @Test
    void loadService() {
        def deserializer = ServiceLoader.load(Deserializer).iterator().next()
        assert deserializer instanceof OrgJsonDeserializer
    }

    @Test
    void deserialize() {
        def m = [hello: 42]
        assertEquals m, deserializer.deserialize(Strings.utf8('{"hello":42}'))
    }

    @Test(expected = DeserializationException)
    void deserializeNull() {
        deserializer.deserialize(null)
    }

    @Test(expected = DeserializationException)
    void deserializeEmpty() {
        deserializer.deserialize(new byte[0])
    }

    @Test
    void throwableConvertsToDeserializationException() {

        def t = new Throwable("foo")

        deserializer = new OrgJsonDeserializer() {
            @Override
            Object read(Reader reader) throws IOException {
                throw t
            }
        }

        try {
            deserializer.deserialize(Strings.utf8('whatever'))
            fail()
        } catch (DeserializationException expected) {
            String msg = 'Unable to deserialize JSON bytes: foo'
            assertEquals msg, expected.message
        }
    }

}
