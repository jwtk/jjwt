package io.jsonwebtoken

import io.jsonwebtoken.security.EncryptionAlgorithmName
import org.junit.Test
import static org.junit.Assert.*

class EncryptionAlgorithmNameTest {

    @Test
    void testGetValue() {
        assertEquals 'A128CBC-HS256', EncryptionAlgorithmName.A128CBC_HS256.getValue()
        assertEquals 'A192CBC-HS384', EncryptionAlgorithmName.A192CBC_HS384.getValue()
        assertEquals 'A256CBC-HS512', EncryptionAlgorithmName.A256CBC_HS512.getValue()
        assertEquals 'A128GCM', EncryptionAlgorithmName.A128GCM.getValue()
        assertEquals 'A192GCM', EncryptionAlgorithmName.A192GCM.getValue()
        assertEquals 'A256GCM', EncryptionAlgorithmName.A256GCM.getValue()
    }

    @Test
    void testGetDescription() {
        assertEquals 'AES_128_CBC_HMAC_SHA_256 authenticated encryption algorithm, as defined in https://tools.ietf.org/html/rfc7518#section-5.2.3', EncryptionAlgorithmName.A128CBC_HS256.getDescription()
        assertEquals 'AES_192_CBC_HMAC_SHA_384 authenticated encryption algorithm, as defined in https://tools.ietf.org/html/rfc7518#section-5.2.4', EncryptionAlgorithmName.A192CBC_HS384.getDescription()
        assertEquals 'AES_256_CBC_HMAC_SHA_512 authenticated encryption algorithm, as defined in https://tools.ietf.org/html/rfc7518#section-5.2.5', EncryptionAlgorithmName.A256CBC_HS512.getDescription()
        assertEquals 'AES GCM using 128-bit key', EncryptionAlgorithmName.A128GCM.getDescription()
        assertEquals 'AES GCM using 192-bit key', EncryptionAlgorithmName.A192GCM.getDescription()
        assertEquals 'AES GCM using 256-bit key', EncryptionAlgorithmName.A256GCM.getDescription()
    }

    @Test
    void testGetJcaName() {
        for( def name : EncryptionAlgorithmName.values() ) {
            if (name.getValue().contains("GCM")) {
                assertEquals 'AES/GCM/NoPadding', name.getJcaName()
            } else {
                assertEquals 'AES/CBC/PKCS5Padding', name.getJcaName()
            }
        }
    }

    @Test
    void testToString() {
        for( def name : EncryptionAlgorithmName.values() ) {
            assertEquals name.toString(), name.getValue()
        }
    }

    @Test
    void testForName() {
        def name = EncryptionAlgorithmName.forName('A128GCM')
        assertSame name, EncryptionAlgorithmName.A128GCM
    }

    @Test
    void testForNameFailure() {
        try {
            EncryptionAlgorithmName.forName('foo')
            fail()
        } catch (IllegalArgumentException expected) {
        }
    }
}
