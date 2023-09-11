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
package io.jsonwebtoken.impl.io;

import io.jsonwebtoken.impl.lang.Converter;
import io.jsonwebtoken.impl.lang.Function;
import io.jsonwebtoken.io.DeserializationException;
import io.jsonwebtoken.io.Deserializer;
import io.jsonwebtoken.io.Parser;
import io.jsonwebtoken.lang.Assert;

import java.nio.charset.StandardCharsets;
import java.util.Map;

public class ConvertingParser<T> implements Parser<T> {

    private final Deserializer<?> deserializer;
    private final Converter<T, Object> converter;
    private final Function<Throwable, RuntimeException> exceptionHandler;

    public ConvertingParser(Deserializer<Map<String, ?>> deserializer, Converter<T, Object> converter,
                            Function<Throwable, RuntimeException> exceptionHandler) {
        this.deserializer = Assert.notNull(deserializer, "Deserializer cannot be null.");
        this.converter = Assert.notNull(converter, "Converter canot be null.");
        this.exceptionHandler = Assert.notNull(exceptionHandler, "exceptionHandler function cannot be null.");
    }

    private RuntimeException doThrow(Throwable t) {
        DeserializationException e = t instanceof DeserializationException ? (DeserializationException) t :
                new DeserializationException("Unable to deserialize JSON: " + t.getMessage(), t);
        throw Assert.notNull(this.exceptionHandler.apply(e), "Exception handler cannot return null.");
    }

    private Map<String, ?> deserialize(String json) {
        Assert.hasText(json, "JSON string cannot be null or empty.");
        byte[] data = json.getBytes(StandardCharsets.UTF_8);
        try {
            return deserialize(data);
        } catch (Throwable t) {
            throw doThrow(t);
        }
    }

    @SuppressWarnings("unchecked")
    private Map<String, ?> deserialize(byte[] data) {
        Object val = this.deserializer.deserialize(data);
        if (val == null) {
            String msg = "Deserialized data resulted in a null value; cannot create Map<String,?>";
            throw new DeserializationException(msg);
        }
        if (!(val instanceof Map)) {
            String msg = "Deserialized data is not a JSON Object; cannot create Map<String,?>";
            throw new DeserializationException(msg);
        }
        // JSON Specification requires all JSON Objects to have string-only keys.  So instead of
        // checking that the val.keySet() has all Strings, we blindly cast to a Map<String,?>
        // since input would rarely, if ever have non-string keys.  Even if it did, the resulting
        // ClassCastException would be caught by the calling deserialize(String) method above.
        return (Map<String, ?>) val;
    }

    @Override

    public final T parse(String input) {
        Map<String, ?> m = deserialize(input);
        return this.converter.applyFrom(m);
    }
}
