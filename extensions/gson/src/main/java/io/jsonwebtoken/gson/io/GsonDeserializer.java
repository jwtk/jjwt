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
import io.jsonwebtoken.io.AbstractDeserializer;
import io.jsonwebtoken.lang.Assert;

import java.io.Reader;

public class GsonDeserializer<T> extends AbstractDeserializer<T> {

    private final Class<T> returnType;
    protected final Gson gson;

    public GsonDeserializer() {
        this(GsonSerializer.DEFAULT_GSON);
    }

    @SuppressWarnings("unchecked")
    public GsonDeserializer(Gson gson) {
        this(gson, (Class<T>) Object.class);
    }

    private GsonDeserializer(Gson gson, Class<T> returnType) {
        Assert.notNull(gson, "gson cannot be null.");
        Assert.notNull(returnType, "Return type cannot be null.");
        this.gson = gson;
        this.returnType = returnType;
    }

    @Override
    protected T doDeserialize(Reader reader) {
        return gson.fromJson(reader, returnType);
    }
}
