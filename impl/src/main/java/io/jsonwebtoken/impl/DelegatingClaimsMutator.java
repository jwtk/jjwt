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
import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.lang.Collections;
import io.jsonwebtoken.lang.MapMutator;
import io.jsonwebtoken.lang.Strings;

import java.util.Collection;
import java.util.Date;
import java.util.LinkedHashSet;
import java.util.Set;

/**
 * @param <T> subclass type
 * @since JJWT_RELEASE_VERSION
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
        return audienceSingle(aud);
    }

    private Set<String> getAudience() {
        // caller expects that we're working with a String<Set> so ensure that:
        if (!this.DELEGATE.PARAMS.get(AUDIENCE_STRING.getId()).supports(Collections.emptySet())) {
            String existing = get(AUDIENCE_STRING);
            remove(AUDIENCE_STRING.getId()); // clear out any canonical/idiomatic values since we're replacing
            setDelegate(this.DELEGATE.replace(DefaultClaims.AUDIENCE));
            if (Strings.hasText(existing)) {
                put(DefaultClaims.AUDIENCE, Collections.setOf(existing)); // replace as Set
            }
        }
        Set<String> aud = get(DefaultClaims.AUDIENCE);
        return aud != null ? aud : Collections.<String>emptySet();
    }

    @Override
    public T audienceSingle(String aud) {
        if (!Strings.hasText(aud)) {
            return put(DefaultClaims.AUDIENCE, null);
        }
        // otherwise it's an actual single string, we need to ensure that we can represent it as a single
        // string by swapping out the AUDIENCE param if necessary:
        if (this.DELEGATE.PARAMS.get(AUDIENCE_STRING.getId()).supports(Collections.emptySet())) { // need to swap:
            remove(AUDIENCE_STRING.getId()); //remove any existing value, as conversion will throw an exception
            setDelegate(this.DELEGATE.replace(AUDIENCE_STRING));
        }
        return put(AUDIENCE_STRING, aud);
    }

    @Override
    public T audience(String aud) {
        aud = Assert.hasText(Strings.clean(aud), "Audience string value cannot be null or empty.");
        Set<String> set = new LinkedHashSet<>(getAudience());
        set.add(aud);
        return audience(set);
    }

    @Override
    public T audience(Collection<String> aud) {
        getAudience(); //coerce to Set<String> if necessary
        return put(DefaultClaims.AUDIENCE, Collections.asSet(aud));
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
