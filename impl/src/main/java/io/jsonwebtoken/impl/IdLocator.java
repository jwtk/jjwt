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
import io.jsonwebtoken.JweHeader;
import io.jsonwebtoken.JwsHeader;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.impl.lang.Field;
import io.jsonwebtoken.impl.lang.Function;
import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.lang.Strings;

public class IdLocator<H extends Header<H>, R> implements Function<H, R> {

    private final Field<String> headerField;
    private final String requiredMsg;
    private final boolean headerValueRequired;

    private final Function<String, R> registry;

    public IdLocator(Field<String> field, String requiredMsg, Function<String, R> registry) {
        this.headerField = Assert.notNull(field, "Header field cannot be null.");
        this.registry = Assert.notNull(registry, "Registry cannot be null.");
        this.headerValueRequired = Strings.hasText(requiredMsg);
        this.requiredMsg = requiredMsg;
    }

    private static String type(Header<?> header) {
        if (header instanceof JweHeader) {
            return "JWE";
        } else if (header instanceof JwsHeader) {
            return "JWS";
        } else {
            return "JWT";
        }
    }

    @Override
    public R apply(H header) {

        Assert.notNull(header, "Header argument cannot be null.");

        Object val = header.get(this.headerField.getId());
        String id = val != null ? String.valueOf(val) : null;

        if (this.headerValueRequired && !Strings.hasText(id)) {
            throw new MalformedJwtException(requiredMsg);
        }

        R instance = registry.apply(id);

        if (this.headerValueRequired && instance == null) {
            String msg = "Unrecognized " + type(header) + " " + this.headerField + " header value: " + id;
            throw new UnsupportedJwtException(msg);
        }

        return instance;
    }
}