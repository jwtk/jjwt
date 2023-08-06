package io.jsonwebtoken.impl;

import io.jsonwebtoken.ClaimsMutator;
import io.jsonwebtoken.impl.lang.DelegatingMapMutator;
import io.jsonwebtoken.impl.lang.Field;
import io.jsonwebtoken.lang.MapMutator;

import java.util.Date;

/**
 * @param <T> subclass type
 * @since JJWT_RELEASE_VERSION
 */
public class DelegatingClaimsMutator<T extends MapMutator<String, Object, T> & ClaimsMutator<T>>
        extends DelegatingMapMutator<String, Object, FieldMap, T>
        implements ClaimsMutator<T> {

    protected DelegatingClaimsMutator() {
        super(new FieldMap(DefaultClaims.FIELDS));
    }

    <F> T put(Field<F> field, Object value) {
        this.DELEGATE.put(field, value);
        return self();
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
        return audience(aud);
    }

    @Override
    public T audience(String aud) {
        return put(DefaultClaims.AUDIENCE, aud);
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
