/*
 * Copyright © 2026 jsonwebtoken.io
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
package io.jsonwebtoken.issues

import io.jsonwebtoken.Claims
import io.jsonwebtoken.Jws
import io.jsonwebtoken.JwtParserBuilder
import io.jsonwebtoken.Jwts
import io.jsonwebtoken.gson.io.GsonDeserializer
import io.jsonwebtoken.gson.io.GsonSerializer
import org.junit.Test

import static org.junit.Assert.assertEquals

/**
 * Asserts that the {@code JwtParserBuilder} {@code require*} methods work as expected when using the
 * {@code jjwt-gson} extension.
 *
 * @see <a href="https://github.com/jwtk/jjwt/issues/762">JJWT Issue 762</a>
 */
class Issue762Test {

    private static final Date now() {
        // JWT NumericDate values have seconds precision:
        long seconds = System.currentTimeMillis().intdiv(1000L) as long
        return new Date(seconds * 1000L)
    }

    @Test
    void testRequireWithGson() {
        def key = Jwts.SIG.HS256.key().build()
        Date iat = now()
        Date exp = new Date(iat.getTime() + (24 * 60 * 60 * 1000L))
        String id = UUID.randomUUID().toString()

        String jws = Jwts.builder()
                .json(new GsonSerializer())
                .header().keyId('myKeyId').and()
                .subject('Joe')
                .issuer('Aaron')
                .audience().add('Abel').and()
                .expiration(exp)
                .notBefore(iat)
                .issuedAt(iat)
                .id(id)
                .claim('exampleClaim', 'Adam')
                .claim('intClaim', 42)
                .claim('longClaim', Long.MAX_VALUE)
                .signWith(key)
                .compressWith(Jwts.ZIP.GZIP)
                .compact()

        def parser = { ->
            Jwts.parser().json(new GsonDeserializer()).clockSkewSeconds(3 * 60).verifyWith(key)
        }
        def parse = { JwtParserBuilder builder -> builder.build().parseSignedClaims(jws) }

        Jws<Claims> result = parse(parser())
        assertEquals 'Joe', result.getPayload().getSubject()

        // none of these should throw an exception:
        parse(parser().requireSubject('Joe'))
        parse(parser().requireIssuer('Aaron'))
        parse(parser().requireAudience('Abel'))
        parse(parser().requireExpiration(exp))
        parse(parser().requireNotBefore(iat))
        parse(parser().requireIssuedAt(iat))
        parse(parser().requireId(id))
        parse(parser().require('exampleClaim', 'Adam'))
        parse(parser().require('intClaim', 42))
        parse(parser().require('longClaim', Long.MAX_VALUE))
    }
}
