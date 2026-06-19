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
import io.jsonwebtoken.security.ConfidentialValue;

import java.lang.reflect.Type;

/**
 * A {@link JsonSerializer} that can extract and write a {@link ConfidentialValue}'s wrapped value as JSON.
 *
 * @since JJWT_RELEASE_VERSION
 */
public final class GsonConfidentialValueSerializer implements JsonSerializer<ConfidentialValue<?>> {

    /**
     * This class's singleton instance.
     */
    public static final GsonConfidentialValueSerializer INSTANCE = new GsonConfidentialValueSerializer();

    /**
     * Extracts the {@code confidentialValue}'s wrapped raw value and serializes it to a {@code JsonElement}.
     *
     * @param confidentialValue the wrapper for the underlying raw value to be extracted.
     * @param type              the actual type (fully genericized version) of the source object.
     * @param ctx               the serialization context used to write the raw value to JSON
     * @return the element to include in the rendered JSON output
     */
    @Override
    public JsonElement serialize(ConfidentialValue<?> confidentialValue, Type type, JsonSerializationContext ctx) {
        Object value = confidentialValue.get();
        return ctx.serialize(value);
    }
}
