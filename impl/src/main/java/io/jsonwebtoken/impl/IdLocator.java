/*
 * Copyright (C) 2021 jsonwebtoken.io
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
package io.jsonwebtoken.impl;

import io.jsonwebtoken.Header;
import io.jsonwebtoken.Identifiable;
import io.jsonwebtoken.Locator;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.impl.lang.Parameter;
import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.lang.Registry;
import io.jsonwebtoken.lang.Strings;

import java.util.function.Function;

public class IdLocator<H extends Header, R extends Identifiable> implements Locator<R>, Function<H, R> {

    private final Parameter<String> param;
    private final Registry<String, R> registry;
    private final String algType;
    private final String behavior;
    private final String requiredMsg;

    public IdLocator(Parameter<String> param, Registry<String, R> registry, String algType, String behavior, String requiredExceptionMessage) {
        this.param = Assert.notNull(param, "Header param cannot be null.");
        this.registry = Assert.notNull(registry, "Registry cannot be null.");
        this.algType = Assert.hasText(algType, "algType cannot be null or empty.");
        this.behavior = Assert.hasText(behavior, "behavior cannot be null or empty.");
        this.requiredMsg = Strings.clean(requiredExceptionMessage);
    }

    @Override
    public R locate(Header header) {

        Object val = header.get(this.param.getId());
        String id = val != null ? val.toString() : null;

        if (!Strings.hasText(id)) {
            if (this.requiredMsg != null) { // a msg was provided, so the value is required:
                throw new MalformedJwtException(requiredMsg);
            }
            return null; // otherwise header value not required, so short circuit
        }

        try {
            return registry.forKey(id);
        } catch (Exception e) {
            StringBuilder sb = new StringBuilder("Unsupported ")
                    .append(DefaultHeader.nameOf(header))
                    .append(" ")
                    .append(this.param)
                    .append(" value '").append(id).append("'");
            if (this.registry.isEmpty()) {
                sb.append(": ")
                        .append(this.behavior)
                        .append(" is disabled (no ")
                        .append(this.algType)
                        .append(" algorithms have been configured)");
            }
            sb.append(".");
            String msg = sb.toString();
            throw new UnsupportedJwtException(msg, e);
        }
    }

    @Override
    public R apply(H header) {
        return locate(header);
    }
}