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

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonToken;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.deser.std.StdScalarDeserializer;
import io.jsonwebtoken.lang.DateFormats;

import java.io.IOException;
import java.text.ParseException;
import java.time.Instant;

/**
 * Deserializes {@link Instant} values from ISO-8601 strings (as written by {@link JacksonInstantSerializer}) or from
 * integral numbers representing milliseconds since the epoch, consistent with JJWT's {@code Claims.get(name,
 * Instant.class)} conversion heuristics, and without requiring the {@code jackson-datatype-jsr310} module.
 *
 * @since 0.14.0
 */
final class JacksonInstantDeserializer extends StdScalarDeserializer<Instant> {

    static final JacksonInstantDeserializer INSTANCE = new JacksonInstantDeserializer();

    public JacksonInstantDeserializer() {
        super(Instant.class);
    }

    @Override
    public Instant deserialize(JsonParser p, DeserializationContext ctx) throws IOException {
        JsonToken token = p.currentToken();
        if (token == JsonToken.VALUE_NUMBER_INT) {
            return Instant.ofEpochMilli(p.getLongValue());
        }
        if (token == JsonToken.VALUE_STRING) {
            String value = p.getText().trim();
            try {
                return DateFormats.parseIso8601Instant(value);
            } catch (ParseException e) {
                return (Instant) ctx.handleWeirdStringValue(Instant.class, value,
                        "not an ISO-8601-formatted string: %s", e.getMessage());
            }
        }
        return (Instant) ctx.handleUnexpectedToken(Instant.class, p);
    }
}
