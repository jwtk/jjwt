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
import com.google.gson.GsonBuilder;
import com.google.gson.ToNumberPolicy;
import io.jsonwebtoken.io.AbstractSerializer;
import io.jsonwebtoken.io.Encoders;
import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.lang.Objects;
import io.jsonwebtoken.security.ConfidentialValue;

import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.nio.charset.StandardCharsets;

public class GsonSerializer<T> extends AbstractSerializer<T> {

    static final Gson DEFAULT_GSON = new GsonBuilder()
            .setObjectToNumberStrategy(ToNumberPolicy.LONG_OR_DOUBLE)
            .setNumberToNumberStrategy(ToNumberPolicy.LONG_OR_DOUBLE)
            .registerTypeHierarchyAdapter(ConfidentialValue.class, GsonConfidentialValueSerializer.INSTANCE)
            .disableHtmlEscaping().create();

    protected final Gson gson;

    public GsonSerializer() {
        this(DEFAULT_GSON);
    }

    public GsonSerializer(Gson gson) {
        Assert.notNull(gson, "gson cannot be null.");
        this.gson = gson;

        //ensure the necessary type adapter has been registered, and if not, throw an error:
        String json = this.gson.toJson(TestConfidentialValue.INSTANCE);
        if (json.contains("value")) {
            String msg = "Invalid Gson instance - it has not been registered with the necessary " +
                    ConfidentialValue.class.getName() + " type adapter.  When using the GsonBuilder, ensure this " +
                    "type adapter is registered by calling gsonBuilder.registerTypeHierarchyAdapter(" +
                    ConfidentialValue.class.getName() + ".class, " +
                    GsonConfidentialValueSerializer.class.getName() + ".INSTANCE) before calling gsonBuilder.create()";
            throw new IllegalArgumentException(msg);
        }
    }

    @Override
    protected void doSerialize(T t, OutputStream out) {
        Writer writer = new OutputStreamWriter(out, StandardCharsets.UTF_8);
        try {
            Object o = t;
            if (o instanceof byte[]) {
                o = Encoders.BASE64.encode((byte[]) o);
            } else if (o instanceof char[]) {
                o = new String((char[]) o);
            }
            writeValue(o, writer);
        } finally {
            Objects.nullSafeClose(writer);
        }
    }

    protected void writeValue(Object o, java.io.Writer writer) {
        this.gson.toJson(o, writer);
    }

    private static class TestConfidentialValue<T> implements ConfidentialValue<T> {

        private static final TestConfidentialValue<String> INSTANCE = new TestConfidentialValue<>("test");
        private final T value;

        private TestConfidentialValue(T value) {
            this.value = value;
        }

        @Override
        public T get() {
            return value;
        }
    }
}
