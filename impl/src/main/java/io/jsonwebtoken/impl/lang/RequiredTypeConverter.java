/*
 * Copyright © 2021 jsonwebtoken.io
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

/**
 * @since JJWT_RELEASE_VERSION
 */
public class RequiredTypeConverter<T> implements Converter<T, Object> {

    private final Class<T> type;

    public RequiredTypeConverter(Class<T> type) {
        this.type = Assert.notNull(type, "type argument cannot be null.");
    }

    @Override
    public Object applyTo(T t) {
        return t;
    }

    @Override
    public T applyFrom(Object o) {
        if (o == null) {
            return null;
        }
        Class<?> clazz = o.getClass();
        if (!type.isAssignableFrom(clazz)) {
            String msg = "Unsupported value type. Expected: " + type.getName() + ", found: " + clazz.getName();
            throw new IllegalArgumentException(msg);
        }
        return type.cast(o);
    }
}