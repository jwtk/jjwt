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
package io.jsonwebtoken.gson.io;

import com.google.gson.Gson;
import com.google.gson.JsonIOException;
import com.google.gson.JsonParseException;
import com.google.gson.JsonSyntaxException;
import com.google.gson.stream.JsonReader;
import com.google.gson.stream.MalformedJsonException;
import io.jsonwebtoken.io.AbstractDeserializer;
import io.jsonwebtoken.lang.Assert;

import java.io.IOException;
import java.io.Reader;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.HashSet;
import java.util.Set;

public class GsonDeserializer<T> extends AbstractDeserializer<T> {

    private final Class<T> returnType;
    protected final Gson gson;

    /**
     * {@code true} if this instance uses JJWT's default {@link Gson} instance, in which case duplicate JSON member
     * names are rejected. Instances supplied via {@link #GsonDeserializer(Gson)} retain Gson's default behavior of
     * silently using the last duplicate value.
     */
    private final boolean rejectDuplicateNames;

    public GsonDeserializer() {
        this(GsonSerializer.DEFAULT_GSON, true);
    }

    public GsonDeserializer(Gson gson) {
        this(gson, false);
    }

    @SuppressWarnings("unchecked")
    private GsonDeserializer(Gson gson, boolean rejectDuplicateNames) {
        this(gson, (Class<T>) Object.class, rejectDuplicateNames);
    }

    private GsonDeserializer(Gson gson, Class<T> returnType, boolean rejectDuplicateNames) {
        Assert.notNull(gson, "gson cannot be null.");
        Assert.notNull(returnType, "Return type cannot be null.");
        this.gson = gson;
        this.returnType = returnType;
        this.rejectDuplicateNames = rejectDuplicateNames;
    }

    @Override
    protected T doDeserialize(Reader reader) {
        if (!this.rejectDuplicateNames) {
            return gson.fromJson(reader, returnType);
        }
        JsonReader jsonReader = new DuplicateNameRejectingJsonReader(reader);
        T value = gson.fromJson(jsonReader, returnType);
        assertFullConsumption(jsonReader);
        return value;
    }

    /**
     * Ensures nothing follows the parsed value, mirroring the check {@code Gson} performs when it creates the
     * {@link JsonReader} itself.  {@code Gson#fromJson(JsonReader, Type)} does not perform it, so supplying our own
     * reader would otherwise accept trailing content.
     *
     * <p>The reader is always strict, and a strict reader reports anything other than the end of the document by
     * throwing {@link MalformedJsonException}, so peeking is all that is required.</p>
     *
     * @param jsonReader the reader used to produce the deserialized value
     */
    private static void assertFullConsumption(JsonReader jsonReader) {
        try {
            jsonReader.peek();
        } catch (MalformedJsonException e) {
            throw new JsonSyntaxException(e);
        } catch (IOException e) {
            throw new JsonIOException(e);
        }
    }

    /**
     * A {@link JsonReader} that rejects JSON objects containing duplicate member names.
     *
     * <p>The JWS and JWT RFCs require member names to be unique and require parsers to either reject such input or
     * use only the lexically last value (see
     * <a href="https://www.rfc-editor.org/rfc/rfc7515#section-4">RFC 7515, Section 4</a> and
     * <a href="https://www.rfc-editor.org/rfc/rfc7519#section-4">RFC 7519, Section 4</a>). Gson does the latter
     * silently, so this reader implements the former to match the behavior JJWT already applies to its default
     * Jackson {@code ObjectMapper}.</p>
     *
     * <p>Detection happens while the document is read, so values are still parsed by Gson itself and no additional
     * pass or buffering is required.</p>
     */
    private static final class DuplicateNameRejectingJsonReader extends JsonReader {

        private final Deque<Set<String>> names = new ArrayDeque<>();

        private DuplicateNameRejectingJsonReader(Reader in) {
            super(in);
        }

        @Override
        public void beginObject() throws IOException {
            super.beginObject();
            this.names.push(new HashSet<String>());
        }

        @Override
        public void endObject() throws IOException {
            super.endObject();
            this.names.pop();
        }

        @Override
        public String nextName() throws IOException {
            String name = super.nextName();
            Set<String> seen = this.names.peek();
            if (seen != null && !seen.add(name)) {
                throw new JsonParseException("Duplicate JSON member name '" + name + "' at " + getPath());
            }
            return name;
        }
    }
}
