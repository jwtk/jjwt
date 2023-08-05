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
import io.jsonwebtoken.impl.lang.DelegatingMapMutator;
import io.jsonwebtoken.impl.lang.Field;

import java.util.Date;

/**
 * @since JJWT_RELEASE_VERSION
 */
@SuppressWarnings("unused") // used via reflection via Jwts.claims()
public final class DefaultClaimsBuilder extends DelegatingMapMutator<String, Object, FieldMap, ClaimsBuilder>
        implements ClaimsBuilder {

    public DefaultClaimsBuilder() {
        super(new FieldMap(DefaultClaims.FIELDS));
    }

    <T> ClaimsBuilder put(Field<T> field, Object value) {
        this.DELEGATE.put(field, value);
        return self();
    }

    @Override
    public ClaimsBuilder setIssuer(String iss) {
        return issuer(iss);
    }

    @Override
    public ClaimsBuilder issuer(String iss) {
        return put(DefaultClaims.ISSUER, iss);
    }

    @Override
    public ClaimsBuilder setSubject(String sub) {
        return subject(sub);
    }

    @Override
    public ClaimsBuilder subject(String sub) {
        return put(DefaultClaims.SUBJECT, sub);
    }

    @Override
    public ClaimsBuilder setAudience(String aud) {
        return audience(aud);
    }

    @Override
    public ClaimsBuilder audience(String aud) {
        return put(DefaultClaims.AUDIENCE, aud);
    }

    @Override
    public ClaimsBuilder setExpiration(Date exp) {
        return expiration(exp);
    }

    @Override
    public ClaimsBuilder expiration(Date exp) {
        return put(DefaultClaims.EXPIRATION, exp);
    }

    @Override
    public ClaimsBuilder setNotBefore(Date nbf) {
        return notBefore(nbf);
    }

    @Override
    public ClaimsBuilder notBefore(Date nbf) {
        return put(DefaultClaims.NOT_BEFORE, nbf);
    }

    @Override
    public ClaimsBuilder setIssuedAt(Date iat) {
        return issuedAt(iat);
    }

    @Override
    public ClaimsBuilder issuedAt(Date iat) {
        return put(DefaultClaims.ISSUED_AT, iat);
    }

    @Override
    public ClaimsBuilder setId(String jti) {
        return id(jti);
    }

    @Override
    public ClaimsBuilder id(String jti) {
        return put(DefaultClaims.JTI, jti);
    }

    @Override
    public Claims build() {
        // ensure a new instance is returned so that the builder may be re-used:
        return new DefaultClaims(this.DELEGATE);
    }
}
