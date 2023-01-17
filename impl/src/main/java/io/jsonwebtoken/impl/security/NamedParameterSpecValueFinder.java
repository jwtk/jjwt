package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.impl.lang.Function;
import io.jsonwebtoken.impl.lang.Functions;
import io.jsonwebtoken.impl.lang.OptionalMethodInvoker;

import java.security.Key;

public class NamedParameterSpecValueFinder implements Function<Key, String> {

    private static final Function<Key, Object> EDEC_KEY_GET_PARAMS =
            new OptionalMethodInvoker<>("java.security.interfaces.EdECKey", "getParams");
    private static final Function<Key, Object> XEC_KEY_GET_PARAMS =
            new OptionalMethodInvoker<>("java.security.interfaces.XECKey", "getParams");
    private static final Function<Object, String> GET_NAME =
            new OptionalMethodInvoker<>("java.security.spec.NamedParameterSpec", "getName");

    private static final Function<Key, String> EDEC_FN = Functions.andThen(EDEC_KEY_GET_PARAMS, GET_NAME);
    private static final Function<Key, String> XEC_FN = Functions.andThen(XEC_KEY_GET_PARAMS, GET_NAME);

    @Override
    public String apply(final Key key) {
        String result = EDEC_FN.apply(key);
        if (result == null) {
            result = XEC_FN.apply(key);
        }
        return result;
    }
}
