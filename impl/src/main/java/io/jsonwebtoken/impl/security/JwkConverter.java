package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.impl.lang.Converter;
import io.jsonwebtoken.security.Identifiable;
import io.jsonwebtoken.security.Jwk;

import java.security.Key;
import java.util.Map;

public interface JwkConverter<K extends Key> extends Identifiable, Converter<K, Map<String,?>> {

    boolean supports(Key key);
}
