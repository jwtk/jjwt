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

import io.jsonwebtoken.impl.lang.Services;
import io.jsonwebtoken.io.Deserializer;
import io.jsonwebtoken.io.Parser;
import io.jsonwebtoken.io.ParserBuilder;

import java.security.Provider;
import java.util.Map;

public abstract class AbstractParserBuilder<T, B extends ParserBuilder<T, B>> implements ParserBuilder<T, B> {

    protected Provider provider;

    protected Deserializer<Map<String, ?>> deserializer;

    @SuppressWarnings("unchecked")
    protected final B self() {
        return (B) this;
    }

    @Override
    public B provider(Provider provider) {
        this.provider = provider;
        return self();
    }

    @Override
    public B deserializer(Deserializer<Map<String, ?>> deserializer) {
        this.deserializer = deserializer;
        return self();
    }

    @Override
    public final Parser<T> build() {
        if (this.deserializer == null) {
            // try to find one based on the services available:
            //noinspection unchecked
            this.deserializer = Services.loadFirst(Deserializer.class);
        }
        return doBuild();
    }

    protected abstract Parser<T> doBuild();
}
