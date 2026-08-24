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
package io.jsonwebtoken.jackson.io;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.ser.std.StdSerializer;
import io.jsonwebtoken.lang.DateFormats;

import java.io.IOException;
import java.time.Instant;

/**
 * Serializes {@link Instant} values as ISO-8601 strings with millisecond precision (e.g.
 * {@code 2026-10-03T10:00:00.123Z}), consistent with how JJWT represents {@code java.util.Date} values in custom
 * claims, and without requiring the {@code jackson-datatype-jsr310} module.
 *
 * @since 0.14.0
 */
final class JacksonInstantSerializer extends StdSerializer<Instant> {

    static final JacksonInstantSerializer INSTANCE = new JacksonInstantSerializer();

    public JacksonInstantSerializer() {
        super(Instant.class);
    }

    @Override
    public void serialize(Instant instant, JsonGenerator generator, SerializerProvider provider) throws IOException {
        generator.writeString(DateFormats.formatIso8601(instant));
    }
}
