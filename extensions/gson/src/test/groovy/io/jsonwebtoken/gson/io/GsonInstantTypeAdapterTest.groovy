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
package io.jsonwebtoken.gson.io

import com.google.gson.Gson
import com.google.gson.GsonBuilder
import com.google.gson.JsonParseException
import org.junit.Test

import java.time.Instant

import static org.junit.Assert.*

class GsonInstantTypeAdapterTest {

    private static final Gson GSON = new GsonBuilder()
            .registerTypeAdapter(Instant, GsonInstantTypeAdapter.INSTANCE).create()

    @Test
    void testWrite() {
        assertEquals '"2026-10-03T10:00:00.123Z"', GSON.toJson(Instant.parse('2026-10-03T10:00:00.123Z'))
    }

    @Test
    void testWriteNull() {
        assertEquals 'null', GsonInstantTypeAdapter.INSTANCE.toJson(null)
    }

    @Test
    void testReadIso8601String() {
        assertEquals Instant.parse('2026-10-03T10:00:00.123Z'),
                GSON.fromJson('"2026-10-03T10:00:00.123Z"', Instant)
    }

    @Test
    void testReadMillis() {
        assertEquals Instant.ofEpochMilli(1791021600123L), GSON.fromJson('1791021600123', Instant)
    }

    @Test
    void testReadNull() {
        assertNull GSON.fromJson('null', Instant)
    }

    @Test
    void testReadInvalidString() {
        try {
            GSON.fromJson('"hello"', Instant)
            fail()
        } catch (JsonParseException expected) {
            assertTrue expected.getMessage().startsWith("Unable to parse 'hello' as an ISO-8601 Instant")
        }
    }
}
