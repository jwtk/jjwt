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
import io.jsonwebtoken.JweHeader;
import io.jsonwebtoken.JwsHeader;
import io.jsonwebtoken.Locator;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.impl.lang.Field;
import io.jsonwebtoken.impl.lang.Function;
import io.jsonwebtoken.impl.lang.IdRegistry;
import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.lang.Collections;
import io.jsonwebtoken.lang.Registry;
import io.jsonwebtoken.lang.Strings;

import java.util.Collection;
import java.util.LinkedHashSet;

public class IdLocator<H extends Header, R extends Identifiable> implements Locator<R>, Function<H, R> {

    private final Field<String> field;
    private final String requiredMsg;
    private final boolean valueRequired;

    private final Registry<String, R> registry;

    public IdLocator(Field<String> field, Registry<String, R> registry, Collection<R> extras, String requiredExceptionMessage) {
        this.field = Assert.notNull(field, "Header field cannot be null.");
        this.requiredMsg = Strings.clean(requiredExceptionMessage);
        this.valueRequired = Strings.hasText(this.requiredMsg);
        Assert.notEmpty(registry, "Registry cannot be null or empty.");
        Collection<R> all = new LinkedHashSet<>(Collections.size(registry) + Collections.size(extras));
        all.addAll(extras);
        all.addAll(registry.values());
        this.registry = new IdRegistry<>(field.getName(), all);
    }

    private static String type(Header header) {
        if (header instanceof JweHeader) {
            return "JWE";
        } else if (header instanceof JwsHeader) {
            return "JWS";
        } else {
            return "JWT";
        }
    }

    @Override
    public R locate(Header header) {
        Assert.notNull(header, "Header argument cannot be null.");

        Object val = header.get(this.field.getId());
        String id = val != null ? val.toString() : null;

        if (!Strings.hasText(id)) {
            if (this.valueRequired) {
                throw new MalformedJwtException(requiredMsg);
            }
            return null; // otherwise header value not required, so short circuit
        }

        try {
            return registry.forKey(id);
        } catch (Exception e) {
            String msg = "Unrecognized " + type(header) + " " + this.field + " header value: " + id;
            throw new UnsupportedJwtException(msg, e);
        }
    }

    @Override
    public R apply(H header) {
        return locate(header);
    }
}