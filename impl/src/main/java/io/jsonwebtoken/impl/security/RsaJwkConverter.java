package io.jsonwebtoken.impl.security;

import java.security.Key;
import java.security.interfaces.RSAKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Map;

public class RsaJwkConverter<K extends Key & RSAKey> extends AbstractJwkConverter<K> {

    static final String TYPE_VALUE = "RSA";
    static final String MODULUS = "n";
    static final String EXPONENT = "e";
    static String PRIVATE_EXPONENT = "d";
    static String FIRST_PRIME = "p";
    static String SECOND_PRIME = "q";
    static String FIRST_CRT_EXPONENT = "dp";
    static String SECOND_CRT_EXPONENT = "dq";
    static String FIRST_CRT_COEFFICIENT = "qi";
    static String OTHER_PRIMES_INFO = "oth";

    public RsaJwkConverter() {
        super("RSA");
    }

    @Override
    public boolean supports(Key key) {
        return key instanceof RSAPublicKey || key instanceof RSAPrivateKey;
    }

    @Override
    public Map<String, ?> applyTo(K key) {
        throw new UnsupportedOperationException("Not yet implemented.");
    }

    @Override
    public K applyFrom(Map<String, ?> jwk) {
        throw new UnsupportedOperationException("Not yet implemented.");
    }
}
