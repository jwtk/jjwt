package io.jsonwebtoken.impl

import static org.junit.Assert.*
import org.junit.Test

class JwtTokenizerTest {

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
