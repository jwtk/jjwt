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
import io.jsonwebtoken.lang.Objects;
import io.jsonwebtoken.lang.Supplier;

public class RedactedSupplier<T> implements Supplier<T> {

    public static final String REDACTED_VALUE = "<redacted>";

    private final T value;

    public RedactedSupplier(T value) {
        this.value = Assert.notNull(value, "value cannot be null.");
    }

    @Override
    public T get() {
        return value;
    }

    @Override
    public int hashCode() {
        return Objects.nullSafeHashCode(value);
    }

    @Override
    public boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if (obj instanceof RedactedSupplier) {
            obj = ((RedactedSupplier<?>) obj).value; // get the wrapped value
        }
        return Objects.nullSafeEquals(this.value, obj);
    }

    @Override
    public String toString() {
        return REDACTED_VALUE;
    }
}
