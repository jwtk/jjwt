/*
 * Copyright © 2022 jsonwebtoken.io
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

import io.jsonwebtoken.Header;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.impl.security.JwkContext;
import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.security.Jwk;
import io.jsonwebtoken.security.MalformedKeyException;

public class RequiredFieldReader implements FieldReadable {

    private final FieldReadable src;

    public RequiredFieldReader(Header<?> header) {
        this(Assert.isInstanceOf(FieldReadable.class, header, "Header implementations must implement FieldReadable."));
    }

    public RequiredFieldReader(FieldReadable src) {
        this.src = Assert.notNull(src, "Source FieldReadable cannot be null.");
        Assert.isInstanceOf(Nameable.class, src, "FieldReadable implementations must implement Nameable.");
    }

    private String name() {
        return ((Nameable) this.src).getName();
    }

    private JwtException malformed(String msg) {
        if (this.src instanceof JwkContext || this.src instanceof Jwk) {
            return new MalformedKeyException(msg);
        } else {
            return new MalformedJwtException(msg);
        }
    }

    @Override
    public <T> T get(Field<T> field) {
        T value = this.src.get(field);
        if (value == null) {
            String msg = name() + " is missing required " + field + " value.";
            throw malformed(msg);
        }
        return value;
    }
}
