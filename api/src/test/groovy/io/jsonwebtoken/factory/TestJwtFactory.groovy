package io.jsonwebtoken.factory

import io.jsonwebtoken.Claims
import io.jsonwebtoken.Header
import io.jsonwebtoken.JwsHeader
import io.jsonwebtoken.JwtBuilder
import io.jsonwebtoken.JwtParser

class TestJwtFactory implements JwtFactory {
    @Override
    Header header() {
        return null
    }

    @Override
    Header header(final Map<String, Object> header) {
        return null
    }

    @Override
    JwsHeader jwsHeader() {
        return null
    }

    @Override
    JwsHeader jwsHeader(final Map<String, Object> header) {
        return null
    }

    @Override
    Claims claims() {
        return null
    }

    @Override
    Claims claims(final Map<String, Object> claim) {
        return null
    }

    @Override
    JwtParser parser() {
        return null
    }

    @Override
    JwtBuilder builder() {
        return null
    }
}