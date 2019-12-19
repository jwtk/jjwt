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
package io.jsonwebtoken.impl

import io.jsonwebtoken.Clock
import io.jsonwebtoken.CompressionCodecResolver
import io.jsonwebtoken.JwtHandler
import io.jsonwebtoken.JwtParser
import io.jsonwebtoken.SigningKeyResolver
import io.jsonwebtoken.io.Decoder
import io.jsonwebtoken.io.Deserializer
import org.junit.Test

import java.security.Key

import static org.easymock.EasyMock.expect
import static org.easymock.EasyMock.mock
import static org.easymock.EasyMock.replay
import static org.easymock.EasyMock.verify
import static org.hamcrest.MatcherAssert.assertThat
import static org.hamcrest.CoreMatchers.is

/**
 * TODO: These mutable methods will be removed pre 1.0, and ImmutableJwtParser will be replaced with the default
 * JwtParser impl.
 *
 * @since 0.11.0
 */
class ImmutableJwtParserTest {

    @Test
    void parseWithHandlerTest() {

        def jwtString = "j.w.t"
        JwtHandler jwtHandler = mock(JwtHandler)
        JwtParser jwtParser = mock(JwtParser)
        Object returnValue = new Object()

        expect(jwtParser.parse(jwtString, jwtHandler)).andReturn(returnValue)
        replay(jwtParser)

        assertThat new ImmutableJwtParser(jwtParser).parse(jwtString, jwtHandler), is(returnValue)

        verify(jwtParser)
    }

    private ImmutableJwtParser jwtParser() {
        return new ImmutableJwtParser(mock(JwtParser))
    }

    @Test(expected=IllegalStateException)
    void requireIdTest() {
        jwtParser().requireId("id")
    }

    @Test(expected=IllegalStateException)
    void requireSubjectTest() {
        jwtParser().requireSubject("subject")
    }

    @Test(expected=IllegalStateException)
    void requireAudienceTest() {
        jwtParser().requireAudience("aud")
    }

    @Test(expected=IllegalStateException)
    void requireIssuerTest() {
        jwtParser().requireIssuer("issuer")
    }

    @Test(expected=IllegalStateException)
    void requireIssuedAtTest() {
        jwtParser().requireIssuedAt(new Date())
    }

    @Test(expected=IllegalStateException)
    void requireExpirationTest() {
        jwtParser().requireExpiration(new Date())
    }

    @Test(expected=IllegalStateException)
    void requireNotBeforeTest() {
        jwtParser().requireNotBefore(new Date())
    }

    @Test(expected=IllegalStateException)
    void requireTest() {
        jwtParser().require("key", "value")
    }

    @Test(expected=IllegalStateException)
    void setClockTest() {
        jwtParser().setClock(mock((Clock)))
    }

    @Test(expected=IllegalStateException)
    void setAllowedClockSkewSecondsTest() {
        jwtParser().setAllowedClockSkewSeconds(1L)
    }

    @Test(expected=IllegalStateException)
    void setSigningKeyBytesTest() {
        jwtParser().setSigningKey("foo".getBytes())
    }

    @Test(expected=IllegalStateException)
    void setSigningKeyStringTest() {
        jwtParser().setSigningKey("foo")
    }

    @Test(expected=IllegalStateException)
    void setSigningKey() {
        jwtParser().setSigningKey(mock(Key))
    }

    @Test(expected=IllegalStateException)
    void setSigningKeyResolverTest() {
        jwtParser().setSigningKeyResolver(mock(SigningKeyResolver))
    }

    @Test(expected=IllegalStateException)
    void setCompressionCodecResolverTest() {
        jwtParser().setCompressionCodecResolver(mock(CompressionCodecResolver))
    }

    @Test(expected=IllegalStateException)
    void base64UrlDecodeWithTest() {
        jwtParser().base64UrlDecodeWith(mock(Decoder))
    }

    @Test(expected=IllegalStateException)
    void deserializeJsonWithTest() {
        jwtParser().deserializeJsonWith(mock(Deserializer))
    }
}
