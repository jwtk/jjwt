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
import com.google.gson.GsonBuilder;
import io.jsonwebtoken.io.Encoders;
import io.jsonwebtoken.io.Writer;
import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.lang.Supplier;

import java.io.IOException;

public class GsonWriter<T> implements Writer<T> {

    static final Gson DEFAULT_GSON = new GsonBuilder()
            .registerTypeHierarchyAdapter(Supplier.class, GsonSupplierSerializer.INSTANCE)
            .disableHtmlEscaping().create();

    protected final Gson gson;

    public GsonWriter() {
        this(DEFAULT_GSON);
    }

    public GsonWriter(Gson gson) {
        Assert.notNull(gson, "gson cannot be null.");
        this.gson = gson;

        //ensure the necessary type adapter has been registered, and if not, throw an error:
        String json = this.gson.toJson(TestSupplier.INSTANCE);
        if (json.contains("value")) {
            String msg = "Invalid Gson instance - it has not been registered with the necessary " +
                    Supplier.class.getName() + " type adapter.  When using the GsonBuilder, ensure this " +
                    "type adapter is registered by calling gsonBuilder.registerTypeHierarchyAdapter(" +
                    Supplier.class.getName() + ".class, " +
                    GsonSupplierSerializer.class.getName() + ".INSTANCE) before calling gsonBuilder.create()";
            throw new IllegalArgumentException(msg);
        }
    }

    @Override
    public void write(java.io.Writer out, T t) throws IOException {
        Assert.notNull(t, "Object to write cannot be null.");
        Assert.notNull(out, "Writer cannot be null.");
        Object o = t;
        try {
            if (o instanceof byte[]) {
                o = Encoders.BASE64.encode((byte[]) t);
            } else if (o instanceof char[]) {
                o = new String((char[]) o);
            }
            writeValue(o, out);
        } catch (Throwable ex) {
            String msg = "Unable to serialize object of type " + o.getClass().getName() + ": " + ex.getMessage();
            throw new IOException(msg, ex);
        }
    }

    protected void writeValue(Object o, java.io.Writer writer) {
        this.gson.toJson(o, writer);
    }

    private static class TestSupplier<T> implements Supplier<T> {

        private static final TestSupplier<String> INSTANCE = new TestSupplier<>("test");
        private final T value;

        private TestSupplier(T value) {
            this.value = value;
        }

        @Override
        public T get() {
            return value;
        }
    }
}
