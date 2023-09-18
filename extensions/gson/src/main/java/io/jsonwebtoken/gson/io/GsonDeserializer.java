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
import io.jsonwebtoken.io.DeserializationException;
import io.jsonwebtoken.io.Deserializer;
import io.jsonwebtoken.lang.Objects;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.Reader;

@SuppressWarnings("DeprecatedIsStillUsed")
@Deprecated
public class GsonDeserializer<T> extends GsonReader<T> implements Deserializer<T> {

    public GsonDeserializer() {
        super();
    }

    public GsonDeserializer(Gson gson) {
        super(gson);
    }

    @SuppressWarnings("deprecation")
    @Deprecated
    @Override
    public T deserialize(byte[] bytes) throws DeserializationException {
        try {
            return readValue(bytes);
        } catch (Throwable t) {
            String msg = "Unable to deserialize JSON: " + t.getMessage();
            throw new DeserializationException(msg, t);
        }
    }

    @Deprecated
    protected T readValue(byte[] bytes) throws IOException {
        Reader reader = new InputStreamReader(new ByteArrayInputStream(bytes));
        try {
            return read(reader);
        } finally {
            Objects.nullSafeClose(reader);
        }
    }
}
