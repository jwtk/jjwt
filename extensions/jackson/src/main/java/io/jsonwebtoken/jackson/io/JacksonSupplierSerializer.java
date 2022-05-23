/*
 * Copyright (C) 2022 jsonwebtoken.io
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

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.JsonSerializer;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.ser.std.StdSerializer;
import io.jsonwebtoken.lang.Supplier;

import java.io.IOException;

final class JacksonSupplierSerializer extends StdSerializer<Supplier<?>> {

    static final JacksonSupplierSerializer INSTANCE = new JacksonSupplierSerializer();

    public JacksonSupplierSerializer() {
        super(Supplier.class, false);
    }

    @Override
    public void serialize(Supplier<?> supplier, JsonGenerator generator, SerializerProvider provider) throws IOException {
        Object value = supplier.get();

        if (value == null) {
            provider.defaultSerializeNull(generator);
            return;
        }

        Class<?> clazz = value.getClass();
        JsonSerializer<Object> ser = provider.findTypedValueSerializer(clazz, true, null);
        ser.serialize(value, generator, provider);
    }
}
