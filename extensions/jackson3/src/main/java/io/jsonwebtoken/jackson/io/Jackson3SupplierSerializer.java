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


import io.jsonwebtoken.lang.Supplier;
import tools.jackson.core.JacksonException;
import tools.jackson.core.JsonGenerator;
import tools.jackson.databind.SerializationContext;
import tools.jackson.databind.ValueSerializer;
import tools.jackson.databind.ser.std.StdSerializer;

final class Jackson3SupplierSerializer extends StdSerializer<Supplier<?>> {

    static final Jackson3SupplierSerializer INSTANCE = new Jackson3SupplierSerializer();

    public Jackson3SupplierSerializer() {
        super(Supplier.class, false);
    }

    /**
     * @param supplier
     * @param generator
     * @param provider
     * @throws JacksonException
     */
    @Override
    public void serialize(Supplier<?> supplier, JsonGenerator generator, SerializationContext provider) throws JacksonException {
        Object value = supplier.get();

        if (value == null) {
            provider.defaultSerializeNullValue(generator);
            return;
        }

        Class<?> clazz = value.getClass();
        ValueSerializer<Object> ser = provider.findTypedValueSerializer(clazz, true);
        ser.serialize(value, generator, provider);
    }
}
