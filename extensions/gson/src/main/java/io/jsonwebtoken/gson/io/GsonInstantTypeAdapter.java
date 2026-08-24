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
package io.jsonwebtoken.gson.io;

import com.google.gson.JsonParseException;
import com.google.gson.TypeAdapter;
import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonToken;
import com.google.gson.stream.JsonWriter;
import io.jsonwebtoken.lang.DateFormats;

import java.io.IOException;
import java.text.ParseException;
import java.time.Instant;

/**
 * Gson {@link TypeAdapter} that writes {@link Instant} values as ISO-8601 strings with millisecond precision (e.g.
 * {@code 2026-10-03T10:00:00.123Z}), consistent with how JJWT represents {@code java.util.Date} values in custom
 * claims. When reading, ISO-8601 strings and integral numbers (milliseconds since the epoch) are supported.
 *
 * <p>JJWT's default {@code Gson} instance already has this adapter registered. If you specify your own {@code Gson}
 * instance and use {@code Instant} values in custom claims, register it via
 * {@code gsonBuilder.registerTypeAdapter(Instant.class, GsonInstantTypeAdapter.INSTANCE)}.</p>
 *
 * @since 0.14.0
 */
public final class GsonInstantTypeAdapter extends TypeAdapter<Instant> {

    public static final TypeAdapter<Instant> INSTANCE = new GsonInstantTypeAdapter().nullSafe();

    private GsonInstantTypeAdapter() {
    }

    @Override
    public void write(JsonWriter out, Instant instant) throws IOException {
        out.value(DateFormats.formatIso8601(instant));
    }

    @Override
    public Instant read(JsonReader in) throws IOException {
        if (in.peek() == JsonToken.NUMBER) {
            return Instant.ofEpochMilli(in.nextLong());
        }
        String value = in.nextString();
        try {
            return DateFormats.parseIso8601Instant(value);
        } catch (ParseException e) {
            throw new JsonParseException("Unable to parse '" + value + "' as an ISO-8601 Instant: " +
                    e.getMessage(), e);
        }
    }
}
