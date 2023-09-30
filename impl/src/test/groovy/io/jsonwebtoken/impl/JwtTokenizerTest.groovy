/*
 * Copyright (C) 2018 jsonwebtoken.io
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

import io.jsonwebtoken.MalformedJwtException
import io.jsonwebtoken.impl.io.Streams
import org.junit.Before
import org.junit.Test

import java.nio.CharBuffer

import static org.junit.Assert.*

class JwtTokenizerTest {

    private JwtTokenizer tokenizer

    @Before
    void setUp() {
        tokenizer = new JwtTokenizer()
    }

    private def tokenize(CharSequence s) {
        return tokenizer.tokenize(Streams.reader(s))
    }

    @Test(expected = MalformedJwtException)
    void testParseWithWhitespaceInBase64UrlHeader() {
        def input = 'header .body.signature'
        tokenize(input)
    }

    @Test(expected = MalformedJwtException)
    void testParseWithWhitespaceInBase64UrlBody() {
        def input = 'header. body.signature'
        tokenize(input)
    }

    @Test(expected = MalformedJwtException)
    void testParseWithWhitespaceInBase64UrlSignature() {
        def input = 'header.body. signature'
        tokenize(input)
    }

    @Test(expected = MalformedJwtException)
    void testParseWithWhitespaceInBase64UrlJweBody() {
        def input = 'header.encryptedKey.initializationVector. body.authenticationTag'
        tokenize(input)
    }

    @Test(expected = MalformedJwtException)
    void testParseWithWhitespaceInBase64UrlJweTag() {
        def input = 'header.encryptedKey.initializationVector.body. authenticationTag'
        tokenize(input)
    }

    @Test
    void readerExceptionResultsInMalformedJwtException() {
        IOException ioe = new IOException('foo')
        def reader = new StringReader('hello') {
            @Override
            int read(char[] chars) throws IOException {
                throw ioe
            }
        }
        try {
            JwtTokenizer.read(reader, new char[0])
            fail()
        } catch (MalformedJwtException expected) {
            String msg = 'Unable to read compact JWT: foo'
            assertEquals msg, expected.message
            assertSame ioe, expected.cause
        }
    }

    @Test
    void testEmptyJws() {
        def input = CharBuffer.wrap('header..digest'.toCharArray())
        def t = tokenize(input)
        assertTrue t instanceof TokenizedJwt
        assertFalse t instanceof TokenizedJwe
        assertEquals 'header', t.getProtected().toString()
        assertEquals '', t.getPayload().toString()
        assertEquals 'digest', t.getDigest().toString()
    }

    @Test
    void testJwe() {

        def input = 'header.encryptedKey.initializationVector.body.authenticationTag'

        def t = tokenize(input)

        assertNotNull t
        assertTrue t instanceof TokenizedJwe
        TokenizedJwe tjwe = (TokenizedJwe) t
        assertEquals 'header', tjwe.getProtected()
        assertEquals 'encryptedKey', tjwe.getEncryptedKey()
        assertEquals 'initializationVector', tjwe.getIv()
        assertEquals 'body', tjwe.getPayload()
        assertEquals 'authenticationTag', tjwe.getDigest()
    }
}
