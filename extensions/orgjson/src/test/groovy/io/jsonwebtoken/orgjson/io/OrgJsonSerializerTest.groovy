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

import io.jsonwebtoken.io.SerializationException
import io.jsonwebtoken.io.Serializer
import io.jsonwebtoken.lang.Strings
import org.junit.Before
import org.junit.Test

import static org.hamcrest.CoreMatchers.instanceOf
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
        assertThat(serializer, instanceOf(OrgJsonSerializer))
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
            String msg = "Unable to serialize object of type java.lang.Object to JSON: $causeMsg"
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
