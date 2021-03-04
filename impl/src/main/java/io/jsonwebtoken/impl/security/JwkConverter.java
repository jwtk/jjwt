package io.jsonwebtoken.impl.security;

import java.security.Key;
import java.util.Map;

public interface JwkConverter {

    Key toKey(Map<String,?> jwk);

    Map<String, String> toJwk(Key key);
}
