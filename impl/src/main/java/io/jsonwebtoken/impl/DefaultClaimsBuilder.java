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
package io.jsonwebtoken.impl;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ClaimsBuilder;
import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.lang.Collections;

import java.util.Date;
import java.util.Map;

@SuppressWarnings("unused") // used via reflection via Jwts.claims()
public final class DefaultClaimsBuilder implements ClaimsBuilder {

    final DefaultClaims claims;

    public DefaultClaimsBuilder() {
        this.claims = new DefaultClaims();
    }

    @Override
    public ClaimsBuilder put(String name, Object value) {
        Assert.hasText(name, "Claim property name cannot be null or empty.");
        this.claims.put(name, value);
        return this;
    }

    @Override
    public ClaimsBuilder remove(String key) {
        this.claims.remove(key);
        return this;
    }

    @Override
    public ClaimsBuilder putAll(Map<? extends String, ?> m) {
        if (!Collections.isEmpty(m)) {
            for (Map.Entry<? extends String, ?> entry : m.entrySet()) {
                put(entry.getKey(), entry.getValue());
            }
        }
        return this;
    }

    @Override
    public ClaimsBuilder clear() {
        this.claims.clear();
        return this;
    }

    @Override
    public ClaimsBuilder setIssuer(String iss) {
        claims.setIssuer(iss);
        return this;
    }

    @Override
    public ClaimsBuilder setSubject(String sub) {
        claims.setSubject(sub);
        return this;
    }

    @Override
    public ClaimsBuilder setAudience(String aud) {
        claims.setAudience(aud);
        return this;
    }

    @Override
    public ClaimsBuilder setExpiration(Date exp) {
        claims.setExpiration(exp);
        return this;
    }

    @Override
    public ClaimsBuilder setNotBefore(Date nbf) {
        claims.setNotBefore(nbf);
        return this;
    }

    @Override
    public ClaimsBuilder setIssuedAt(Date iat) {
        claims.setIssuedAt(iat);
        return this;
    }

    @Override
    public ClaimsBuilder setId(String jti) {
        claims.setId(jti);
        return this;
    }

    @Override
    public Claims build() {
        // ensure a new instance is returned so that the builder may be re-used:
        return new DefaultClaims(claims);
    }
}
