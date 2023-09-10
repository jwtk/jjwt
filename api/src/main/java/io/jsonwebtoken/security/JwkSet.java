package io.jsonwebtoken.security;

import java.util.Collection;
import java.util.Map;

public interface JwkSet extends Map<String, Object> {

    Collection<? extends Jwk<?>> getKeys();

}
