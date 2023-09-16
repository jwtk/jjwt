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

public class NullSafeConverter<A, B> implements Converter<A, B> {

    private final Converter<A, B> converter;

    public NullSafeConverter(Converter<A, B> converter) {
        this.converter = Assert.notNull(converter, "Delegate converter cannot be null.");
    }

    @Override
    public B applyTo(A a) {
        return a == null ? null : converter.applyTo(a);
    }

    @Override
    public A applyFrom(B b) {
        return b == null ? null : converter.applyFrom(b);
    }
}
