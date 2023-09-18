/*
 * Copyright © 2023 jsonwebtoken.io
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
import io.jsonwebtoken.io.Reader;
import io.jsonwebtoken.lang.Assert;

import java.io.IOException;

public class GsonReader<T> implements Reader<T> {

    private final Class<T> returnType;
    protected final Gson gson;

    public GsonReader() {
        this(GsonWriter.DEFAULT_GSON);
    }

    @SuppressWarnings("unchecked")
    public GsonReader(Gson gson) {
        this(gson, (Class<T>) Object.class);
    }

    private GsonReader(Gson gson, Class<T> returnType) {
        Assert.notNull(gson, "gson cannot be null.");
        Assert.notNull(returnType, "Return type cannot be null.");
        this.gson = gson;
        this.returnType = returnType;
    }

    @Override
    public T read(java.io.Reader in) throws IOException {
        try {
            return readValue(in);
        } catch (Throwable t) {
            String msg = "Unable to read JSON as a " + returnType.getName() + " instance: " + t.getMessage();
            throw new IOException(msg, t);
        }
    }

    protected T readValue(java.io.Reader reader) {
        return gson.fromJson(reader, returnType);
    }
}
