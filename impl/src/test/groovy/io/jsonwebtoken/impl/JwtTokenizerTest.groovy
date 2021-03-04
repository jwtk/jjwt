package io.jsonwebtoken.impl

import io.jsonwebtoken.MalformedJwtException

import static org.junit.Assert.*
import org.junit.Test

class JwtTokenizerTest {

    @Test(expected= MalformedJwtException)
    void testParseWithWhitespaceInBase64UrlHeader() {
        def input = 'header .body.signature'
        new JwtTokenizer().tokenize(input)
    }

    @Test(expected= MalformedJwtException)
    void testParseWithWhitespaceInBase64UrlBody() {
        def input = 'header. body.signature'
        new JwtTokenizer().tokenize(input)
    }

    @Test(expected= MalformedJwtException)
    void testParseWithWhitespaceInBase64UrlSignature() {
        def input = 'header.body. signature'
        new JwtTokenizer().tokenize(input)
    }

    @Test(expected= MalformedJwtException)
    void testParseWithWhitespaceInBase64UrlJweBody() {
        def input = 'header.encryptedKey.initializationVector. body.authenticationTag'
        new JwtTokenizer().tokenize(input)
    }

    @Test(expected= MalformedJwtException)
    void testParseWithWhitespaceInBase64UrlJweTag() {
        def input = 'header.encryptedKey.initializationVector.body. authenticationTag'
        new JwtTokenizer().tokenize(input)
    }

    @Test
    void testJwe() {

        def input = 'header.encryptedKey.initializationVector.body.authenticationTag'

        def t = new JwtTokenizer().tokenize(input)

        assertNotNull t
        assertTrue t instanceof TokenizedJwe
        TokenizedJwe tjwe = (TokenizedJwe)t
        assertEquals 'header', tjwe.getProtected()
        assertEquals 'encryptedKey', tjwe.getEncryptedKey()
        assertEquals 'initializationVector', tjwe.getIv()
        assertEquals 'body', tjwe.getBody()
        assertEquals 'authenticationTag', tjwe.getDigest()
    }
}
