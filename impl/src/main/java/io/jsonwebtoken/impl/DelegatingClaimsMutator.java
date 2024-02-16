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

import io.jsonwebtoken.ClaimsMutator;
import io.jsonwebtoken.impl.lang.DelegatingMapMutator;
import io.jsonwebtoken.impl.lang.Parameter;
import io.jsonwebtoken.impl.lang.Parameters;
import io.jsonwebtoken.lang.Collections;
import io.jsonwebtoken.lang.MapMutator;
import io.jsonwebtoken.lang.Strings;

import java.util.Date;
import java.util.Map;
import java.util.Set;

/**
 * @param <T> subclass type
 * @since 0.12.0
 */
public class DelegatingClaimsMutator<T extends MapMutator<String, Object, T> & ClaimsMutator<T>>
        extends DelegatingMapMutator<String, Object, ParameterMap, T>
        implements ClaimsMutator<T> {

    private static final Parameter<String> AUDIENCE_STRING =
            Parameters.string(DefaultClaims.AUDIENCE.getId(), DefaultClaims.AUDIENCE.getName());

    protected DelegatingClaimsMutator() {
        super(new ParameterMap(DefaultClaims.PARAMS));
    }

    <F> T put(Parameter<F> param, F value) {
        this.DELEGATE.put(param, value);
        return self();
    }

    @Override // override starting in 0.12.4
    public Object put(String key, Object value) {
        if (AUDIENCE_STRING.getId().equals(key)) { // https://github.com/jwtk/jjwt/issues/890
            if (value instanceof String) {
                Object existing = get(key);
                //noinspection deprecation
                audience().single((String) value);
                return existing;
            }
            // otherwise ensure that the Parameter type is the RFC-default data type (JSON Array of Strings):
            getAudience();
        }
        // otherwise retain expected behavior:
        return super.put(key, value);
    }

    @Override // overridden starting in 0.12.4
    public void putAll(Map<? extends String, ?> m) {
        if (m == null) return;
        for (Map.Entry<? extends String, ?> entry : m.entrySet()) {
            String s = entry.getKey();
            put(s, entry.getValue()); // ensure local put is called per https://github.com/jwtk/jjwt/issues/890
        }
    }

    <F> F get(Parameter<F> param) {
        return this.DELEGATE.get(param);
    }

    @Override
    public T setIssuer(String iss) {
        return issuer(iss);
    }

    @Override
    public T issuer(String iss) {
        return put(DefaultClaims.ISSUER, iss);
    }

    @Override
    public T setSubject(String sub) {
        return subject(sub);
    }

    @Override
    public T subject(String sub) {
        return put(DefaultClaims.SUBJECT, sub);
    }

    @Override
    public T setAudience(String aud) {
        //noinspection deprecation
        return audience().single(aud);
    }

    private Set<String> getAudience() {
        // caller expects that we're working with a String<Set> so ensure that:
        if (!this.DELEGATE.PARAMS.get(AUDIENCE_STRING.getId()).supports(Collections.emptySet())) {
            String existing = get(AUDIENCE_STRING);
            remove(AUDIENCE_STRING.getId()); // clear out any canonical/idiomatic values since we're replacing
            setDelegate(this.DELEGATE.replace(DefaultClaims.AUDIENCE));
            put(DefaultClaims.AUDIENCE, Collections.setOf(existing)); // replace as Set
        }
        return get(DefaultClaims.AUDIENCE);
    }

    private T audienceSingle(String aud) {
        if (!Strings.hasText(aud)) {
            return put(DefaultClaims.AUDIENCE, null);
        }
        // otherwise it's an actual single string, we need to ensure that we can represent it as a single
        // string by swapping out the AUDIENCE param:
        remove(AUDIENCE_STRING.getId()); //remove any existing value, as conversion will throw an exception
        setDelegate(this.DELEGATE.replace(AUDIENCE_STRING));
        return put(AUDIENCE_STRING, aud);
    }

    @Override
    public AudienceCollection<T> audience() {
        return new AbstractAudienceCollection<T>(self(), getAudience()) {
            @Override
            public T single(String audience) {
                return audienceSingle(audience);
                // DO NOT call changed() here - we don't want to replace the value with a collection
            }

            @Override
            protected void changed() {
                put(DefaultClaims.AUDIENCE, Collections.asSet(getCollection()));
            }
        };
    }

    @Override
    public T setExpiration(Date exp) {
        return expiration(exp);
    }

    @Override
    public T expiration(Date exp) {
        return put(DefaultClaims.EXPIRATION, exp);
    }

    @Override
    public T setNotBefore(Date nbf) {
        return notBefore(nbf);
    }

    @Override
    public T notBefore(Date nbf) {
        return put(DefaultClaims.NOT_BEFORE, nbf);
    }

    @Override
    public T setIssuedAt(Date iat) {
        return issuedAt(iat);
    }

    @Override
    public T issuedAt(Date iat) {
        return put(DefaultClaims.ISSUED_AT, iat);
    }

    @Override
    public T setId(String jti) {
        return id(jti);
    }

    @Override
    public T id(String jti) {
        return put(DefaultClaims.JTI, jti);
    }
}
