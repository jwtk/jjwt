package io.jsonwebtoken.security;

import io.jsonwebtoken.lang.Parser;

public interface JwkSetParser<I> extends Parser<I, JwkSet> {

    JwkSet parse(I input);
}
