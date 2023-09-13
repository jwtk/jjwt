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

public class RequiredParameterReader implements ParameterReadable {

    private final ParameterReadable src;

    public RequiredParameterReader(Header header) {
        this(Assert.isInstanceOf(ParameterReadable.class, header, "Header implementations must implement ParameterReadable."));
    }

    public RequiredParameterReader(ParameterReadable src) {
        this.src = Assert.notNull(src, "Source ParameterReadable cannot be null.");
        Assert.isInstanceOf(Nameable.class, src, "ParameterReadable implementations must implement Nameable.");
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
    public <T> T get(Parameter<T> param) {
        T value = this.src.get(param);
        if (value == null) {
            String msg = name() + " is missing required " + param + " value.";
            throw malformed(msg);
        }
        return value;
    }
}
