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

public class CompoundConverter<A, B, C> implements Converter<A, C> {

    private final Converter<A, B> first;
    private final Converter<B, C> second;

    public CompoundConverter(Converter<A, B> first, Converter<B, C> second) {
        this.first = Assert.notNull(first, "First converter cannot be null.");
        this.second = Assert.notNull(second, "Second converter cannot be null.");
    }

    @Override
    public C applyTo(A a) {
        B b = first.applyTo(a);
        return second.applyTo(b);
    }

    @Override
    public A applyFrom(C c) {
        B b = second.applyFrom(c);
        return first.applyFrom(b);
    }
}
