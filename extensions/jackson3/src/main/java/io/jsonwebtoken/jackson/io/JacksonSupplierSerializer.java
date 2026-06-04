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

import tools.jackson.core.JsonGenerator;
import tools.jackson.databind.SerializationContext;
import tools.jackson.databind.ValueSerializer;
import tools.jackson.databind.ser.std.StdSerializer;
import io.jsonwebtoken.lang.Supplier;

import java.io.IOException;

final class JacksonSupplierSerializer extends StdSerializer<Supplier<?>> {

    static final JacksonSupplierSerializer INSTANCE = new JacksonSupplierSerializer();

    public JacksonSupplierSerializer() {
        super(Supplier.class, false);
    }

    @Override
    public void serialize(Supplier<?> supplier, JsonGenerator generator, SerializationContext context) {
        Object value = supplier.get();

        if (value == null) {
            try {
                // context.defaultSerializeNull(generator); // Might be gone?
                generator.writeNull();
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
            return;
        }

        Class<?> clazz = value.getClass();
        try {
            // Remove null arg for property?
            ValueSerializer<Object> ser = context.findTypedValueSerializer(clazz, true);
            ser.serialize(value, generator, context);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
