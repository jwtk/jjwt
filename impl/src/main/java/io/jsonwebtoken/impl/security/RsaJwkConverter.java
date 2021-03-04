package io.jsonwebtoken.impl.security;

import java.security.Key;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Map;

public class RsaJwkConverter extends AbstractTypedJwkConverter {

    public RsaJwkConverter() {
        super("RSA");
    }

    @Override
    public boolean supports(Key key) {
        return key instanceof RSAPublicKey || key instanceof RSAPrivateKey;
    }

    @Override
    public Key toKey(Map<String, ?> jwk) {
        throw new UnsupportedOperationException("Not yet implemented.");
    }

    @Override
    public Map<String, String> toJwk(Key key) {
        throw new UnsupportedOperationException("Not yet implemented.");
    }
}
