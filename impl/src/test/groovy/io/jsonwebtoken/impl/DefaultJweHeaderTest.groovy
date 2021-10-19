package io.jsonwebtoken.impl

import io.jsonwebtoken.JweHeader
import org.junit.Test

import static org.junit.Assert.assertEquals

/**
 * @since JJWT_RELEASE_VERSION
 */
class DefaultJweHeaderTest {

    @Test
    void testAlgorithm() {
        JweHeader header = new DefaultJweHeader()
        header.setAlgorithm('foo')
        assertEquals 'foo', header.getAlgorithm()

        header = new DefaultJweHeader([alg: 'bar'])
        assertEquals 'bar', header.getAlgorithm()
    }

    @Test
    void testEncryptionAlgorithm() {
        JweHeader header = new DefaultJweHeader()
        header.put('enc', 'foo')
        assertEquals 'foo', header.getEncryptionAlgorithm()

        header = new DefaultJweHeader([enc: 'bar'])
        assertEquals 'bar', header.getEncryptionAlgorithm()
    }
}
