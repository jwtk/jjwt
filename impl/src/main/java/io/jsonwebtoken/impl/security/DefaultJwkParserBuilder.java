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
package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.impl.lang.Services;
import io.jsonwebtoken.io.Deserializer;
import io.jsonwebtoken.security.JwkParser;
import io.jsonwebtoken.security.JwkParserBuilder;

import java.security.Provider;
import java.util.Map;

@SuppressWarnings("unused") //used via reflection by Jwks.parser()
public class DefaultJwkParserBuilder implements JwkParserBuilder {

    private Provider provider;

    private Deserializer<Map<String,?>> deserializer;

    @Override
    public JwkParserBuilder provider(Provider provider) {
        this.provider = provider;
        return this;
    }

    @Override
    public JwkParserBuilder deserializeJsonWith(Deserializer<Map<String, ?>> deserializer) {
        this.deserializer = deserializer;
        return this;
    }

    @Override
    public JwkParser build() {
        if (this.deserializer == null) {
            // try to find one based on the services available:
            //noinspection unchecked
            this.deserializer = Services.loadFirst(Deserializer.class);
        }

        return new DefaultJwkParser(this.provider, this.deserializer);
    }
}
