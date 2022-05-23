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
package io.jsonwebtoken.gson.io;

import com.google.gson.JsonElement;
import com.google.gson.JsonSerializationContext;
import com.google.gson.JsonSerializer;
import io.jsonwebtoken.lang.Supplier;

import java.lang.reflect.Type;

public final class GsonSupplierSerializer implements JsonSerializer<Supplier<?>> {

    public static final GsonSupplierSerializer INSTANCE = new GsonSupplierSerializer();

    @Override
    public JsonElement serialize(Supplier<?> supplier, Type type, JsonSerializationContext ctx) {
        Object value = supplier.get();
        return ctx.serialize(value);
    }
}
