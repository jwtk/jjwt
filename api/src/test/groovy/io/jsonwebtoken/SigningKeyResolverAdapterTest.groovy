package io.jsonwebtoken

import org.junit.Test

import javax.crypto.spec.SecretKeySpec

import static org.easymock.EasyMock.*
import static org.junit.Assert.*

class SigningKeyResolverAdapterTest {

    @Test(expected=UnsupportedJwtException) //should throw since called but not overridden
    void testDefaultResolveSigningKeyBytesFromClaims() {
        def header = createMock(JwsHeader)
        def claims = createMock(Claims)
        new SigningKeyResolverAdapter().resolveSigningKeyBytes(header, claims)
    }

    @Test(expected=UnsupportedJwtException) //should throw since called but not overridden
    void testDefaultResolveSigningKeyBytesFromStringPayload() {
        def header = createMock(JwsHeader)
        new SigningKeyResolverAdapter().resolveSigningKeyBytes(header, "hi")
    }

    @Test
    void testResolveSigningKeyHmac() {

        JwsHeader header = createMock(JwsHeader)
        Claims claims = createMock(Claims)

        byte[] bytes = new byte[32]
        new Random().nextBytes(bytes)

        expect(header.getAlgorithm()).andReturn("HS256")

        replay header, claims

        def adapter = new SigningKeyResolverAdapter() {
            @Override
            byte[] resolveSigningKeyBytes(JwsHeader h, Claims c) {
                assertSame header, h
                assertSame claims, c
                return bytes
            }
        }

        def key = adapter.resolveSigningKey(header, claims)

        verify header, claims

        assertTrue key instanceof SecretKeySpec
        assertEquals 'HmacSHA256', key.algorithm
        assertTrue Arrays.equals(bytes, key.encoded)
    }

    @Test(expected=IllegalArgumentException)
    void testResolveSigningKeyDefaultWithoutHmac() {
        JwsHeader header = createMock(JwsHeader)
        Claims claims = createMock(Claims)
        expect(header.getAlgorithm()).andReturn("RS256")
        replay header, claims
        new SigningKeyResolverAdapter().resolveSigningKey(header, claims)
    }

    @Test
    void testResolveSigningKeyPayloadHmac() {

        JwsHeader header = createMock(JwsHeader)

        byte[] bytes = new byte[32]
        new Random().nextBytes(bytes)

        expect(header.getAlgorithm()).andReturn("HS256")

        replay header

        def adapter = new SigningKeyResolverAdapter() {
            @Override
            byte[] resolveSigningKeyBytes(JwsHeader h, String s) {
                assertSame header, h
                assertEquals 'hi', s
                return bytes
            }
        }

        def key = adapter.resolveSigningKey(header, 'hi')

        verify header

        assertTrue key instanceof SecretKeySpec
        assertEquals 'HmacSHA256', key.algorithm
        assertTrue Arrays.equals(bytes, key.encoded)
    }

    @Test(expected=IllegalArgumentException)
    void testResolveSigningKeyPayloadWithoutHmac() {
        JwsHeader header = createMock(JwsHeader)
        expect(header.getAlgorithm()).andReturn("RS256")
        replay header
        new SigningKeyResolverAdapter().resolveSigningKey(header, 'hi')
    }
}
