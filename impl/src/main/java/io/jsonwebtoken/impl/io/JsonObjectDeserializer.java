/*
 * Copyright (C) 2021 jsonwebtoken.io
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

import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.impl.lang.Function;
import io.jsonwebtoken.io.DeserializationException;
import io.jsonwebtoken.io.Deserializer;
import io.jsonwebtoken.lang.Assert;

import java.io.Reader;
import java.util.Map;

/**
 * Function that wraps a {@link Deserializer} to add JWT-related error handling.
 *
 * @since 0.11.3 (renamed from JwtDeserializer)
 */
public class JsonObjectDeserializer implements Function<Reader, Map<String, ?>> {

    private static final String MALFORMED_ERROR = "Malformed %s JSON: %s";
    private static final String MALFORMED_COMPLEX_ERROR = "Malformed or excessively complex %s JSON. " +
            "If experienced in a production environment, this could reflect a potential malicious %s, please " +
            "investigate the source further. Cause: %s";

    private final Deserializer<?> deserializer;
    private final String name;

    public JsonObjectDeserializer(Deserializer<?> deserializer, String name) {
        this.deserializer = Assert.notNull(deserializer, "JSON Deserializer cannot be null.");
        this.name = Assert.hasText(name, "name cannot be null or empty.");
    }

    @Override
    public Map<String, ?> apply(Reader in) {
        Assert.notNull(in, "InputStream argument cannot be null.");
        Object value;
        try {
            value = this.deserializer.deserialize(in);
            if (value == null) {
                String msg = "Deserialized data resulted in a null value; cannot create Map<String,?>";
                throw new DeserializationException(msg);
            }
            if (!(value instanceof Map)) {
                String msg = "Deserialized data is not a JSON Object; cannot create Map<String,?>";
                throw new DeserializationException(msg);
            }
            // JSON Specification requires all JSON Objects to have string-only keys.  So instead of
            // checking that the val.keySet() has all Strings, we blindly cast to a Map<String,?>
            // since input would rarely, if ever, have non-string keys.
            //noinspection unchecked
            return (Map<String, ?>) value;
        } catch (StackOverflowError e) {
            String msg = String.format(MALFORMED_COMPLEX_ERROR, this.name, this.name, e.getMessage());
            throw new DeserializationException(msg, e);
        } catch (Throwable t) {
            throw malformed(t);
        }
    }

    protected RuntimeException malformed(Throwable t) {
        String msg = String.format(MALFORMED_ERROR, this.name, t.getMessage());
        throw new MalformedJwtException(msg, t);
    }
}
