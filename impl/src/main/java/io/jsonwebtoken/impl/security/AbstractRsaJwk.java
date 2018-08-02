package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.security.RsaJwk;

@SuppressWarnings("unchecked")
public class AbstractRsaJwk<T extends RsaJwk> extends AbstractJwk<T> implements RsaJwk<T> {

    static final String TYPE_VALUE = "RSA";
    static final String MODULUS = "n";
    static final String EXPONENT = "e";

    AbstractRsaJwk() {
        super(TYPE_VALUE);
    }

    @Override
    public String getModulus() {
        return getString(MODULUS);
    }

    @Override
    public T setModulus(String value) {
        return setRequiredValue(MODULUS, value, "modulus");
    }

    @Override
    public String getExponent() {
        return getString(EXPONENT);
    }

    @Override
    public T setExponent(String value) {
        return setRequiredValue(EXPONENT, value, "exponent");
    }
}
