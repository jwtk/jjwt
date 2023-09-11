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
package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.impl.io.ConvertingParser;
import io.jsonwebtoken.impl.lang.Function;
import io.jsonwebtoken.io.Parser;
import io.jsonwebtoken.security.JwkSet;
import io.jsonwebtoken.security.JwkSetParserBuilder;
import io.jsonwebtoken.security.MalformedKeySetException;

public class DefaultJwkSetParserBuilder extends AbstractJwkParserBuilder<JwkSet, JwkSetParserBuilder>
        implements JwkSetParserBuilder {
    @Override
    public Parser<JwkSet> doBuild() {
        JwkSetConverter converter = new JwkSetConverter(new JwkBuilderSupplier(this.provider, this.operationPolicy));
        return new ConvertingParser<>(this.deserializer, converter,
                new Function<Throwable, RuntimeException>() {
                    @Override
                    public RuntimeException apply(Throwable t) {
                        String msg = "Unable to deserialize JWK Set: " + t.getMessage();
                        return new MalformedKeySetException(msg, t);
                    }
                });
    }
}
