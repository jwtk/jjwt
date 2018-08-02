package io.jsonwebtoken.impl.security;

import java.security.Key;

public interface TypedJwkConverter extends JwkConverter {

    String getKeyType();

    boolean supports(Key key);

}
