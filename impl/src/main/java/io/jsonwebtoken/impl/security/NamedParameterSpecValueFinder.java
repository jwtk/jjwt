package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.impl.lang.Function;
import io.jsonwebtoken.impl.lang.Functions;
import io.jsonwebtoken.impl.lang.OptionalMethodInvoker;

import java.security.Key;
import java.security.spec.AlgorithmParameterSpec;

public class NamedParameterSpecValueFinder implements Function<Key, String> {

    private static final Function<Key, AlgorithmParameterSpec> EDEC_KEY_GET_PARAMS =
            new OptionalMethodInvoker<>("java.security.interfaces.EdECKey", "getParams");
    private static final Function<Key, AlgorithmParameterSpec> XEC_KEY_GET_PARAMS =
            new OptionalMethodInvoker<>("java.security.interfaces.XECKey", "getParams");
    private static final Function<Object, String> GET_NAME =
            new OptionalMethodInvoker<>("java.security.spec.NamedParameterSpec", "getName");

    private static final Function<Key, String> COMPOSED = Functions.andThen(Functions.firstResult(EDEC_KEY_GET_PARAMS, XEC_KEY_GET_PARAMS), GET_NAME);

    @Override
    public String apply(final Key key) {
        return COMPOSED.apply(key);
    }
}
