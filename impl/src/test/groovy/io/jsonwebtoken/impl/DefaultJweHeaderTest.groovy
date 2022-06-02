package io.jsonwebtoken.impl

import io.jsonwebtoken.impl.security.Randoms
import io.jsonwebtoken.impl.security.TestKeys
import io.jsonwebtoken.io.Encoders
import io.jsonwebtoken.security.Jwks
import org.junit.Before
import org.junit.Test

import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPublicKey
import java.util.concurrent.atomic.AtomicInteger

import static org.junit.Assert.*

/**
 * @since JJWT_RELEASE_VERSION
 */
class DefaultJweHeaderTest {

    private DefaultJweHeader header

    @Before
    void setUp() {
        header = new DefaultJweHeader()
    }

    @Test
    void testEncryptionAlgorithm() {
        header.put('enc', 'foo')
        assertEquals 'foo', header.getEncryptionAlgorithm()

        header = new DefaultJweHeader([enc: 'bar'])
        assertEquals 'bar', header.getEncryptionAlgorithm()
    }

    @Test
    void testGetName() {
        assertEquals 'JWE header', header.getName()
    }

    @Test
    void testEpkWithSecretJwk() {
        def jwk = Jwks.builder().forKey(TestKeys.HS256).build()
        def values = new LinkedHashMap(jwk) //extract values to remove JWK type
        try {
            header.put('epk', values)
            fail()
        } catch (IllegalArgumentException expected) {
            String msg = "Invalid JWE header 'epk' (Ephemeral Public Key) value: {kty=oct, k=<redacted>}. " +
                    "Value must be an EC Public JWK, not a Secret JWK."
            assertEquals msg, expected.getMessage()
        }
    }

    @Test
    void testEpkWithPrivateJwk() {
        def jwk = Jwks.builder().forKey(TestKeys.ES256.pair.private as ECPrivateKey).build()
        def values = new LinkedHashMap(jwk) //extract values to remove JWK type
        try {
            header.put('epk', values)
            fail()
        } catch (IllegalArgumentException expected) {
            String msg = "Invalid JWE header 'epk' (Ephemeral Public Key) value: {kty=EC, crv=P-256, " +
                    "x=xNKMMIsawShLG4LYxpNP0gqdgK_K69UXCLt3AE3zp-Q, y=_vzQymVtA7RHRTfBWZo75mxPgDkE8g7bdHI3siSuJOk, " +
                    "d=<redacted>}. Value must be an EC Public JWK, not an EC Private JWK."
            assertEquals msg, expected.getMessage()
        }
    }

    @Test
    void testEpkWithRsaPublicJwk() {
        def jwk = Jwks.builder().forKey(TestKeys.RS256.pair.public as RSAPublicKey).build()
        def values = new LinkedHashMap(jwk) //extract values to remove JWK type
        try {
            header.put('epk', values)
            fail()
        } catch (IllegalArgumentException expected) {
            String msg = "Invalid JWE header 'epk' (Ephemeral Public Key) value: {kty=RSA, " +
                    "n=zkH0MwxQ2cUFWsvOPVFqI_dk2EFTjQolCy97mI5_wYCbaOoZ9Rm7c675mAeemRtNzgNVEz7m298ENqNGqPk2Nv3pBJ_" +
                    "XCaybBlp61CLez7dQ2h5jUFEJ6FJcjeKHS-MwXr56t2ISdfLNMYtVIxjvXQcYx5VmS4mIqTxj5gVGtQVi0GXdH6SvpdKV" +
                    "0fjE9KOhjsdBfKQzZfcQlusHg8pThwvjpMwCZnkxCS0RKa9y4-5-7MkC33-8-neZUzS7b6NdFxh6T_pMXpkf8d81fzVo4" +
                    "ZBMloweW0_l8MOdVxeX7M_7XSC1ank5i3IEZcotLmJYMwEo7rMpZVLevEQ118Eo8Q, " +
                    "e=AQAB}. Value must be an EC Public JWK, not an RSA Public JWK."
            assertEquals msg, expected.getMessage()
        }
    }

    @Test
    void testEpkWithEcPublicJwkValues() {
        def jwk = Jwks.builder().forKey(TestKeys.ES256.pair.public as ECPublicKey).build()
        def values = new LinkedHashMap(jwk) //extract values to remove JWK type
        header.put('epk', values)
        assertEquals jwk, header.get('epk')
    }

    @Test
    void testEpkWithInvalidEcPublicJwk() {
        def jwk = Jwks.builder().forKey(TestKeys.ES256.pair.public as ECPublicKey).build()
        def values = new LinkedHashMap(jwk) // copy fields so we can mutate
        // We have a public JWK for a point on the curve, now swap out the x coordinate for something invalid:
        values.put('x', 'Kg')
        try {
            header.put('epk', values)
            fail()
        } catch (IllegalArgumentException expected) {
            String msg = "Invalid JWE header 'epk' (Ephemeral Public Key) value: {kty=EC, crv=P-256, x=Kg, " +
                    "y=_vzQymVtA7RHRTfBWZo75mxPgDkE8g7bdHI3siSuJOk}. EC JWK x,y coordinates do not exist on " +
                    "elliptic curve 'P-256'. This could be due simply to an incorrectly-created JWK or possibly an " +
                    "attempted Invalid Curve Attack (see https://safecurves.cr.yp.to/twist.html for more " +
                    "information)."
            assertEquals msg, expected.getMessage()
        }
    }

    @Test
    void testEpkWithEcPublicJwk() {
        def jwk = Jwks.builder().forKey(TestKeys.ES256.pair.public as ECPublicKey).build()
        header.put('epk', jwk)
        assertEquals jwk, header.get('epk')
        assertEquals jwk, header.getEphemeralPublicKey()
    }

    @Test
    void testAgreementPartyUInfo() {
        String val = "Party UInfo"
        byte[] info = val.getBytes(StandardCharsets.UTF_8)
        header.setAgreementPartyUInfo(info)
        assertArrayEquals info, header.getAgreementPartyUInfo()
    }

    @Test
    void testAgreementPartyUInfoString() {
        String val = "Party UInfo"
        byte[] info = val.getBytes(StandardCharsets.UTF_8)
        header.setAgreementPartyUInfo(val)
        assertArrayEquals info, header.getAgreementPartyUInfo()
    }

    @Test
    void testEmptyAgreementPartyUInfo() {
        byte[] info = new byte[0]
        header.setAgreementPartyUInfo(info)
        assertNull header.getAgreementPartyUInfo()
    }

    @Test
    void testEmptyAgreementPartyUInfoString() {
        String s = '  '
        header.setAgreementPartyUInfo(s)
        assertNull header.getAgreementPartyUInfo()
    }

    @Test
    void testAgreementPartyVInfo() {
        String val = "Party VInfo"
        byte[] info = val.getBytes(StandardCharsets.UTF_8)
        header.setAgreementPartyVInfo(info)
        assertArrayEquals info, header.getAgreementPartyVInfo()
    }

    @Test
    void testAgreementPartyVInfoString() {
        String val = "Party VInfo"
        byte[] info = val.getBytes(StandardCharsets.UTF_8)
        header.setAgreementPartyVInfo(val)
        assertArrayEquals info, header.getAgreementPartyVInfo()
    }

    @Test
    void testEmptyAgreementPartyVInfo() {
        byte[] info = new byte[0]
        header.setAgreementPartyVInfo(info)
        assertNull header.getAgreementPartyVInfo()
    }

    @Test
    void testEmptyAgreementPartyVInfoString() {
        String s = '  '
        header.setAgreementPartyVInfo(s)
        assertNull header.getAgreementPartyVInfo()
    }

    @Test
    void testIv() {
        byte[] bytes = new byte[12]
        Randoms.secureRandom().nextBytes(bytes)
        header.put('iv', bytes)
        assertEquals Encoders.BASE64URL.encode(bytes), header.get('iv')
        assertTrue MessageDigest.isEqual(bytes, header.getInitializationVector())
    }

    @Test
    void testIvWithIncorrectSize() {
        byte[] bytes = new byte[7]
        Randoms.secureRandom().nextBytes(bytes)
        try {
            header.put('iv', bytes)
            fail()
        } catch (IllegalArgumentException expected) {
            String msg = "Invalid JWE header 'iv' (Initialization Vector) value. " +
                    "Byte array must be exactly 96 bits (12 bytes). Found 56 bits (7 bytes)"
            assertEquals msg, expected.getMessage()
        }
    }

    @Test
    void testTag() {
        byte[] bytes = new byte[16]
        Randoms.secureRandom().nextBytes(bytes)
        header.put('tag', bytes)
        assertEquals Encoders.BASE64URL.encode(bytes), header.get('tag')
        assertTrue MessageDigest.isEqual(bytes, header.getAuthenticationTag())
    }

    @Test
    void testTagWithIncorrectSize() {
        byte[] bytes = new byte[15]
        Randoms.secureRandom().nextBytes(bytes)
        try {
            header.put('tag', bytes)
            fail()
        } catch (IllegalArgumentException expected) {
            String msg = "Invalid JWE header 'tag' (Authentication Tag) value. " +
                    "Byte array must be exactly 128 bits (16 bytes). Found 120 bits (15 bytes)"
            assertEquals msg, expected.getMessage()
        }
    }

    @Test
    void testP2cByte() {
        header.put('p2c', Byte.MAX_VALUE)
        assertEquals 127, header.getPbes2Count()
    }

    @Test
    void testP2cShort() {
        header.put('p2c', Short.MAX_VALUE)
        assertEquals 32767, header.getPbes2Count()
    }

    @Test
    void testP2cInt() {
        header.put('p2c', Integer.MAX_VALUE)
        assertEquals 0x7fffffff as Integer, header.getPbes2Count()
    }

    @Test
    void testP2cAtomicInteger() {
        header.put('p2c', new AtomicInteger(Integer.MAX_VALUE))
        assertEquals 0x7fffffff as Integer, header.getPbes2Count()
    }

    @Test
    void testP2cString() {
        header.put('p2c', "100")
        assertEquals 100, header.getPbes2Count()
    }

    @Test
    void testP2cZero() {
        try {
            header.put('p2c', 0)
            fail()
        } catch (IllegalArgumentException expected) {
            String msg = "Invalid JWE header 'p2c' (PBES2 Count) value: 0. Value must be a positive integer."
            assertEquals msg, expected.getMessage()
        }
    }

    @Test
    void testP2cNegative() {
        try {
            header.put('p2c', -1)
            fail()
        } catch (IllegalArgumentException expected) {
            String msg = "Invalid JWE header 'p2c' (PBES2 Count) value: -1. Value must be a positive integer."
            assertEquals msg, expected.getMessage()
        }
    }

    @Test
    void testP2cTooLarge() {
        try {
            header.put('p2c', Long.MAX_VALUE)
            fail()
        } catch (IllegalArgumentException expected) {
            String msg = "Invalid JWE header 'p2c' (PBES2 Count) value: 9223372036854775807. " +
                    "Value cannot be represented as a java.lang.Integer."
            assertEquals msg, expected.getMessage()
        }
    }

    @Test
    void testP2cDecimal() {
        double d = 42.2348423d
        try {
            header.put('p2c', d)
            fail()
        } catch (IllegalArgumentException expected) {
            String msg = "Invalid JWE header 'p2c' (PBES2 Count) value: $d. " +
                    "Value cannot be represented as a java.lang.Integer."
            assertEquals msg, expected.getMessage()
        }
    }

    @Test
    void testPbe2SaltBytes() {
        byte[] salt = new byte[32]
        Randoms.secureRandom().nextBytes(salt)
        header.put('p2s', salt)
        assertEquals Encoders.BASE64URL.encode(salt), header.get('p2s')
        assertArrayEquals salt, header.getPbes2Salt()
    }

    @Test
    void pbe2SaltStringTest() {
        byte[] salt = new byte[32]
        Randoms.secureRandom().nextBytes(salt)
        String val = Encoders.BASE64URL.encode(salt)
        header.put('p2s', val)
        //ensure that even though a Base64Url string was set, we get back a byte[]:
        assertArrayEquals salt, header.getPbes2Salt()
    }
}
