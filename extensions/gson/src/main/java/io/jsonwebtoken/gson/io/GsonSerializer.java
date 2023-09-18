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
import io.jsonwebtoken.io.SerializationException;
import io.jsonwebtoken.io.Serializer;
import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.lang.Objects;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;

@SuppressWarnings("DeprecatedIsStillUsed")
@Deprecated
public class GsonSerializer<T> extends GsonWriter<T> implements Serializer<T> {

    public GsonSerializer() {
        super();
    }

    public GsonSerializer(Gson gson) {
        super(gson);
    }

    @SuppressWarnings("deprecation")
    @Override
    public byte[] serialize(T t) throws SerializationException {
        Assert.notNull(t, "Object to serialize cannot be null.");
        try {
            return writeValueAsBytes(t);
        } catch (Throwable ex) {
            String msg = "Unable to serialize object: " + ex.getMessage();
            throw new SerializationException(msg, ex);
        }
    }

    protected byte[] writeValueAsBytes(T t) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream(256);
        OutputStreamWriter writer = new OutputStreamWriter(baos, StandardCharsets.UTF_8);
        try {
            write(writer, t);
        } finally {
            Objects.nullSafeClose(writer);
        }
        return baos.toByteArray();
    }
}
