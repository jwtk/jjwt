/*
 * Copyright © 2020 jsonwebtoken.io
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
package io.jsonwebtoken.impl.lang;

import io.jsonwebtoken.lang.Assert;

public class EncodedObjectConverter<T> implements Converter<T, Object> {

    private final Class<T> type;
    private final Converter<T, String> converter;

    public EncodedObjectConverter(Class<T> type, Converter<T, String> converter) {
        this.type = Assert.notNull(type, "Value type cannot be null.");
        this.converter = Assert.notNull(converter, "Value converter cannot be null.");
    }

    @Override
    public Object applyTo(T t) {
        Assert.notNull(t, "Value argument cannot be null.");
        return converter.applyTo(t);
    }

    @Override
    public T applyFrom(Object value) {
        Assert.notNull(value, "Value argument cannot be null.");
        if (type.isInstance(value)) {
            return type.cast(value);
        } else if (value instanceof String) {
            return converter.applyFrom((String) value);
        } else {
            String msg = "Values must be either String or " + type.getName() +
                " instances. Value type found: " + value.getClass().getName() + ".";
            throw new IllegalArgumentException(msg);
        }
    }
}
