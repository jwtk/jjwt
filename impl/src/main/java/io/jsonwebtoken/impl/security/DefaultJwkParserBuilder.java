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

import io.jsonwebtoken.impl.io.ConvertingParser;
import io.jsonwebtoken.io.Parser;
import io.jsonwebtoken.security.Jwk;
import io.jsonwebtoken.security.JwkParserBuilder;

public class DefaultJwkParserBuilder extends AbstractJwkParserBuilder<Jwk<?>, JwkParserBuilder>
        implements JwkParserBuilder {
    @Override
    public Parser<Jwk<?>> doBuild() {
        JwkDeserializer deserializer = new JwkDeserializer(this.deserializer);
        JwkBuilderSupplier supplier = new JwkBuilderSupplier(this.provider, this.operationPolicy);
        JwkConverter<Jwk<?>> converter = new JwkConverter<>(supplier);
        return new ConvertingParser<>(deserializer, converter);
    }
}
