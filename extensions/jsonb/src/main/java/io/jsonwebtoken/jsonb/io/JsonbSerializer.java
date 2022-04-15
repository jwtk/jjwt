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
package io.jsonwebtoken.jsonb.io;

import io.jsonwebtoken.io.Encoders;
import io.jsonwebtoken.io.SerializationException;
import io.jsonwebtoken.io.Serializer;
import io.jsonwebtoken.lang.Assert;

import javax.json.bind.Jsonb;
import javax.json.bind.JsonbBuilder;
import javax.json.bind.JsonbException;
import java.nio.charset.StandardCharsets;

import static java.util.Objects.requireNonNull;

/**
 * @since 0.10.0
 */
public class JsonbSerializer<T> implements Serializer<T> {

    static final Jsonb DEFAULT_JSONB = JsonbBuilder.create();

    private final Jsonb jsonb;

    @SuppressWarnings("unused") //used via reflection by RuntimeClasspathDeserializerLocator
    public JsonbSerializer() {
        this(DEFAULT_JSONB);
    }

    @SuppressWarnings("WeakerAccess") //intended for end-users to use when providing a custom ObjectMapper
    public JsonbSerializer(Jsonb jsonb) {
        requireNonNull(jsonb, "Jsonb cannot be null.");
        this.jsonb = jsonb;
    }

    @Override
    public byte[] serialize(T t) throws SerializationException {
        Assert.notNull(t, "Object to serialize cannot be null.");
        try {
            return writeValueAsBytes(t);
        } catch (JsonbException jsonbException) {
            String msg = "Unable to serialize object: " + jsonbException.getMessage();
            throw new SerializationException(msg, jsonbException);
        }
    }

    @SuppressWarnings("WeakerAccess") //for testing
    protected byte[] writeValueAsBytes(T t) {
        final Object obj;

        if (t instanceof byte[]) {
            obj = Encoders.BASE64.encode((byte[]) t);
        } else if (t instanceof char[]) {
            obj = new String((char[]) t);
        } else {
            obj = t;
        }

        return this.jsonb.toJson(obj).getBytes(StandardCharsets.UTF_8);
    }
}
