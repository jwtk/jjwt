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
package io.jsonwebtoken.impl.lang;

import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.lang.Supplier;

public class RedactedValueConverter<T> implements Converter<T, Object> {

    private final Converter<T, Object> delegate;

    public RedactedValueConverter(Converter<T, Object> delegate) {
        this.delegate = Assert.notNull(delegate, "Delegate cannot be null.");
    }

    @Override
    public Object applyTo(T t) {
        Object value = this.delegate.applyTo(t);
        if (value != null && !(value instanceof RedactedSupplier)) {
            value = new RedactedSupplier<>(value);
        }
        return value;
    }

    @Override
    public T applyFrom(Object o) {
        if (o instanceof RedactedSupplier) {
            o = ((Supplier<?>) o).get();
        }
        return this.delegate.applyFrom(o);
    }
}
