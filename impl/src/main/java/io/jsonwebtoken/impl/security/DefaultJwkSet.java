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

import io.jsonwebtoken.impl.ParameterMap;
import io.jsonwebtoken.impl.lang.Converter;
import io.jsonwebtoken.impl.lang.Parameter;
import io.jsonwebtoken.impl.lang.Parameters;
import io.jsonwebtoken.lang.Collections;
import io.jsonwebtoken.security.Jwk;
import io.jsonwebtoken.security.JwkSet;

import java.util.Iterator;
import java.util.Map;
import java.util.Set;

public class DefaultJwkSet extends ParameterMap implements JwkSet {

    private static final String NAME = "JWK Set";

    static Parameter<Set<Jwk<?>>> param(Converter<Jwk<?>, ?> converter) {
        return Parameters.builder(JwkConverter.JWK_CLASS)
                .setConverter(converter).set()
                .setId("keys").setName("JSON Web Keys")
                .setSecret(true)
                .build();
    }

    static final Parameter<Set<Jwk<?>>> KEYS = param(JwkConverter.ANY);

    public DefaultJwkSet(Parameter<Set<Jwk<?>>> param, Map<String, ?> src) {
        super(Parameters.registry(param), src);
    }

    @Override
    public String getName() {
        return NAME;
    }

    @Override
    public Set<Jwk<?>> getKeys() {
        Set<Jwk<?>> jwks = get(KEYS);
        if (Collections.isEmpty(jwks)) {
            return Collections.emptySet();
        }
        return Collections.immutable(jwks);
    }

    @Override
    public Iterator<Jwk<?>> iterator() {
        return getKeys().iterator(); // immutable because of getKeys() return value
    }
}
