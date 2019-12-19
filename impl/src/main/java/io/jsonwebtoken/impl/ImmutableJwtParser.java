/*
 * Copyright (C) 2019 jsonwebtoken.io
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.jsonwebtoken.impl;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Clock;
import io.jsonwebtoken.CompressionCodecResolver;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Header;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwt;
import io.jsonwebtoken.JwtHandler;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SigningKeyResolver;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.io.Decoder;
import io.jsonwebtoken.io.Deserializer;
import io.jsonwebtoken.security.SignatureException;

import java.security.Key;
import java.util.Date;
import java.util.Map;

/**
 * This JwtParser implementation exists as a stop gap until the mutable methods are removed from JwtParser.
 * TODO: remove this class BEFORE 1.0
 * @since 0.11.0
 */
class ImmutableJwtParser implements JwtParser {

    private final JwtParser jwtParser;

    ImmutableJwtParser(JwtParser jwtParser) {
        this.jwtParser = jwtParser;
    }

    private IllegalStateException doNotMutate() {
        return new IllegalStateException("Cannot mutate a JwtParser created from JwtParserBuilder.build(), " +
                "the mutable methods in JwtParser will be removed before version 1.0");
    }

    @Override
    public JwtParser requireId(String id) {
        throw doNotMutate();
    }

    @Override
    public JwtParser requireSubject(String subject) {
        throw doNotMutate();
    }

    @Override
    public JwtParser requireAudience(String audience) {
        throw doNotMutate();
    }

    @Override
    public JwtParser requireIssuer(String issuer) {
        throw doNotMutate();
    }

    @Override
    public JwtParser requireIssuedAt(Date issuedAt) {
        throw doNotMutate();
    }

    @Override
    public JwtParser requireExpiration(Date expiration) {
        throw doNotMutate();
    }

    @Override
    public JwtParser requireNotBefore(Date notBefore) {
        throw doNotMutate();
    }

    @Override
    public JwtParser require(String claimName, Object value) {
        throw doNotMutate();
    }

    @Override
    public JwtParser setClock(Clock clock) {
        throw doNotMutate();
    }

    @Override
    public JwtParser setAllowedClockSkewSeconds(long seconds) {
        throw doNotMutate();
    }

    @Override
    public JwtParser setSigningKey(byte[] key) {
        throw doNotMutate();
    }

    @Override
    public JwtParser setSigningKey(String base64EncodedSecretKey) {
        throw doNotMutate();
    }

    @Override
    public JwtParser setSigningKey(Key key) {
        throw doNotMutate();
    }

    @Override
    public JwtParser setSigningKeyResolver(SigningKeyResolver signingKeyResolver) {
        throw doNotMutate();
    }

    @Override
    public JwtParser setCompressionCodecResolver(CompressionCodecResolver compressionCodecResolver) {
        throw doNotMutate();
    }

    @Override
    public JwtParser base64UrlDecodeWith(Decoder<String, byte[]> base64UrlDecoder) {
        throw doNotMutate();
    }

    @Override
    public JwtParser deserializeJsonWith(Deserializer<Map<String, ?>> deserializer) {
        throw doNotMutate();
    }

    @Override
    public boolean isSigned(String jwt) {
        return this.jwtParser.isSigned(jwt);
    }

    @Override
    public Jwt parse(String jwt) throws ExpiredJwtException, MalformedJwtException, SignatureException, IllegalArgumentException {
        return this.jwtParser.parse(jwt);
    }

    @Override
    public <T> T parse(String jwt, JwtHandler<T> handler) throws ExpiredJwtException, UnsupportedJwtException, MalformedJwtException, SignatureException, IllegalArgumentException {
        return this.jwtParser.parse(jwt, handler);
    }

    @Override
    public Jwt<Header, String> parsePlaintextJwt(String plaintextJwt) throws UnsupportedJwtException, MalformedJwtException, SignatureException, IllegalArgumentException {
        return this.jwtParser.parsePlaintextJwt(plaintextJwt);
    }

    @Override
    public Jwt<Header, Claims> parseClaimsJwt(String claimsJwt) throws ExpiredJwtException, UnsupportedJwtException, MalformedJwtException, SignatureException, IllegalArgumentException {
        return this.jwtParser.parseClaimsJwt(claimsJwt);
    }

    @Override
    public Jws<String> parsePlaintextJws(String plaintextJws) throws UnsupportedJwtException, MalformedJwtException, SignatureException, IllegalArgumentException {
        return this.jwtParser.parsePlaintextJws(plaintextJws);
    }

    @Override
    public Jws<Claims> parseClaimsJws(String claimsJws) throws ExpiredJwtException, UnsupportedJwtException, MalformedJwtException, SignatureException, IllegalArgumentException {
        return this.jwtParser.parseClaimsJws(claimsJws);
    }
}
