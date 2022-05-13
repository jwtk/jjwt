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
package io.jsonwebtoken.security;

import io.jsonwebtoken.lang.Classes;

/**
 * Utility methods for creating
 * <a href="https://datatracker.ietf.org/doc/html/rfc7517">JWKs (JSON Web Keys)</a> with a type-safe builder.
 *
 * @see #builder()
 * @since JJWT_RELEASE_VERSION
 */
public final class Jwks {

    private Jwks() {
    } //prevent instantiation

    private static final String CNAME = "io.jsonwebtoken.impl.security.DefaultProtoJwkBuilder";

    /**
     * Return a new JWK builder instance, allowing for type-safe JWK builder coercion based on a provided key or key pair.
     *
     * @return a new JWK builder instance, allowing for type-safe JWK builder coercion based on a provided key or key pair.
     */
    public static ProtoJwkBuilder<?, ?, ?> builder() {
        return Classes.newInstance(CNAME);
    }
}
