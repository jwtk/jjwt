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
package io.jsonwebtoken.impl.security

import io.jsonwebtoken.security.InvalidKeyException
import io.jsonwebtoken.security.UnsupportedKeyException
import org.junit.Test

import java.security.Key
import java.security.PrivateKey
import java.security.Provider
import java.security.Security

import static org.junit.Assert.*

class MlDsaAlgorithmTest {

    // The ML-DSA AlgorithmIdentifier prefix up to (but excluding) the terminal OID node, as hex:
    private static final String ALG_ID_PREFIX_HEX = '300b06096086480165030403'

    private static byte[] hex(String s) {
        s = s.replaceAll('[^0-9a-fA-F]', '')
        byte[] out = new byte[(int) (s.length() / 2)]
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(s.substring(i * 2, i * 2 + 2), 16)
        }
        return out
    }

    private static String seedHex() {
        return '00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff' // any 32 bytes
    }

    /** PKCS#8 encoding using the RFC 9964-aligned {@code seed} CHOICE alternative. */
    private static byte[] seedP8(String oidTerminal = '11') {
        return hex("3034 020100 ${ALG_ID_PREFIX_HEX}${oidTerminal} 0422 8020 ${seedHex()}")
    }

    /** Same as {@link #seedP8} but with a long-form (2-byte) outer SEQUENCE length. */
    private static byte[] seedP8LongForm() {
        return hex("30820034 020100 ${ALG_ID_PREFIX_HEX}11 0422 8020 ${seedHex()}")
    }

    /** PKCS#8 encoding using the {@code both} CHOICE alternative: SEQUENCE of seed and expandedKey. */
    private static byte[] bothP8() {
        return hex("303c 020100 ${ALG_ID_PREFIX_HEX}11 042a 3028 0420 ${seedHex()} 0404 aabbccdd")
    }

    /** PKCS#8 encoding using the {@code expandedKey} CHOICE alternative, from which no seed can be recovered. */
    private static byte[] expandedP8() {
        return hex("301a 020100 ${ALG_ID_PREFIX_HEX}11 0408 0406 aabbccddeeff")
    }

    @Test
    void testFindById() {
        assertNull MlDsaAlgorithm.findById(null)
        assertNull MlDsaAlgorithm.findById('nope')
        assertSame MlDsaAlgorithm.ML_DSA_65, MlDsaAlgorithm.findById('ML-DSA-65')
    }

    @Test
    void testFindByKeyNull() {
        assertNull MlDsaAlgorithm.findByKey(null)
    }

    @Test
    void testFindByKeySpecificAlgorithmName() { // e.g. BouncyCastle key naming
        Key key = new TestKey(algorithm: 'ML-DSA-87')
        assertSame MlDsaAlgorithm.ML_DSA_87, MlDsaAlgorithm.findByKey(key)
    }

    @Test
    void testFindByKeyGenericNameWithoutEncoding() { // e.g. an HSM key that doesn't expose its encoding
        Key key = new TestKey(algorithm: 'ML-DSA')
        assertNull MlDsaAlgorithm.findByKey(key)
    }

    @Test
    void testFindByKeyEncodingWithoutMlDsaOid() {
        Key key = new TestKey(algorithm: 'ML-DSA', encoded: hex('deadbeefdeadbeefdeadbeefdeadbeef'))
        assertNull MlDsaAlgorithm.findByKey(key)
    }

    @Test
    void testFindByKeyEncodingEndsAtOidPrefix() { // OID prefix present but terminal node byte missing
        Key key = new TestKey(algorithm: 'ML-DSA', encoded: hex(ALG_ID_PREFIX_HEX))
        assertNull MlDsaAlgorithm.findByKey(key)
    }

    @Test
    void testFindByKeyUnknownOidTerminalNode() {
        Key key = new TestKey(algorithm: 'ML-DSA', encoded: hex("${ALG_ID_PREFIX_HEX}2a"))
        assertNull MlDsaAlgorithm.findByKey(key)
    }

    @Test
    void testFindByKeyByOid() { // the JDK SUN provider reports the generic 'ML-DSA' name for all parameter sets
        Key key = new TestKey(algorithm: 'ML-DSA', encoded: hex("${ALG_ID_PREFIX_HEX}12"))
        assertSame MlDsaAlgorithm.ML_DSA_65, MlDsaAlgorithm.findByKey(key)
    }

    @Test
    void testIsMlDsa() {
        assertFalse MlDsaAlgorithm.isMlDsa(null)
        assertFalse MlDsaAlgorithm.isMlDsa(new TestKey(algorithm: 'RSA'))
        assertTrue MlDsaAlgorithm.isMlDsa(new TestKey(algorithm: 'ML-DSA')) // generic name
        assertTrue MlDsaAlgorithm.isMlDsa(new TestKey(algorithm: 'ML-DSA-44')) // parameter set name
    }

    @Test
    void testForKeyUnrecognized() {
        try {
            MlDsaAlgorithm.forKey(new TestKey(algorithm: 'EC'))
            fail()
        } catch (InvalidKeyException expected) {
            assertTrue expected.getMessage().startsWith('Unrecognized ML-DSA key: ')
        }
    }

    @Test
    void testAssertMlDsa() {
        Key key = new TestKey(algorithm: 'ML-DSA-44')
        assertSame key, MlDsaAlgorithm.assertMlDsa(key)
    }

    @Test
    void testForId() {
        assertSame MlDsaAlgorithm.ML_DSA_44, MlDsaAlgorithm.forId('ML-DSA-44')
        try {
            MlDsaAlgorithm.forId('ML-KEM-768')
            fail()
        } catch (UnsupportedKeyException expected) {
            assertTrue expected.getMessage().contains("'ML-KEM-768'")
        }
    }

    @Test
    void testToString() {
        assertEquals 'ML-DSA-44', MlDsaAlgorithm.ML_DSA_44.toString()
    }

    @Test
    void testGetPublicKeyMaterialWithWrongLengthEncoding() {
        def key = new TestPublicKey(algorithm: 'ML-DSA-44', encoded: hex('deadbeef'))
        try {
            MlDsaAlgorithm.ML_DSA_44.getPublicKeyMaterial(key)
            fail()
        } catch (InvalidKeyException expected) {
            assertTrue expected.getMessage().contains('Invalid ML-DSA-44 X.509 encoding')
        }
    }

    @Test
    void testGetPublicKeyMaterialWithWrongPrefix() {
        byte[] encoded = new byte[22 + 1312] // correct total length for ML-DSA-44, but not a valid prefix
        def key = new TestPublicKey(algorithm: 'ML-DSA-44', encoded: encoded)
        try {
            MlDsaAlgorithm.ML_DSA_44.getPublicKeyMaterial(key)
            fail()
        } catch (InvalidKeyException expected) {
            assertTrue expected.getMessage().contains('Invalid ML-DSA-44 X.509 encoding')
        }
    }

    @Test
    void testGetSeedFromSeedChoice() {
        def key = new TestPrivateKey(algorithm: 'ML-DSA-44', encoded: seedP8())
        assertArrayEquals hex(seedHex()), MlDsaAlgorithm.ML_DSA_44.getSeed(key)
    }

    @Test
    void testGetSeedFromSeedChoiceWithLongFormLength() {
        def key = new TestPrivateKey(algorithm: 'ML-DSA-44', encoded: seedP8LongForm())
        assertArrayEquals hex(seedHex()), MlDsaAlgorithm.ML_DSA_44.getSeed(key)
    }

    @Test
    void testGetSeedFromBothChoice() { // e.g. BouncyCastle's private key encoding
        def key = new TestPrivateKey(algorithm: 'ML-DSA-44', encoded: bothP8())
        assertArrayEquals hex(seedHex()), MlDsaAlgorithm.ML_DSA_44.getSeed(key)
    }

    @Test
    void testGetSeedFromExpandedKeyChoice() { // e.g. a JDK 24 to 26 private key encoding: seed not recoverable
        def key = new TestPrivateKey(algorithm: 'ML-DSA-44', encoded: expandedP8())
        try {
            MlDsaAlgorithm.ML_DSA_44.getSeed(key)
            fail()
        } catch (InvalidKeyException expected) {
            assertTrue expected.getMessage().contains('expanded private key instead of the seed')
        }
    }

    private static void assertMalformed(String p8hex) {
        def key = new TestPrivateKey(algorithm: 'ML-DSA-44', encoded: hex(p8hex))
        try {
            MlDsaAlgorithm.ML_DSA_44.getSeed(key)
            fail("Expected malformed encoding rejection for: " + p8hex)
        } catch (InvalidKeyException expected) {
            assertEquals 'Malformed ML-DSA-44 PKCS#8 private key encoding.', expected.getMessage()
        }
    }

    @Test
    void testGetSeedMalformedEncodings() {
        assertMalformed '30' // shorter than a minimal SEQUENCE header
        assertMalformed '3100' // not a SEQUENCE
        assertMalformed '3082' // long-form length with missing length octets
        assertMalformed '3000' // SEQUENCE too short to contain a PKCS#8 header
        assertMalformed "3034 020100 ${ALG_ID_PREFIX_HEX}11 0522 8020 ${seedHex()}" // privateKey is not an OCTET STRING
        assertMalformed "3012 020100 ${ALG_ID_PREFIX_HEX}11 0400" // empty privateKey OCTET STRING
        assertMalformed "3011 020100 ${ALG_ID_PREFIX_HEX}11 04" // encoding ends right after the OCTET STRING tag
        assertMalformed "3014 020100 ${ALG_ID_PREFIX_HEX}11 0402 a100" // unrecognized CHOICE alternative
        assertMalformed "3035 020100 ${ALG_ID_PREFIX_HEX}11 0423 8021 ${seedHex()}00" // seed length is not 32
        assertMalformed "3018 020100 ${ALG_ID_PREFIX_HEX}11 0406 8020 00112233" // truncated seed value
        assertMalformed "3016 020100 ${ALG_ID_PREFIX_HEX}11 0404 3002 0500" // 'both' without a seed OCTET STRING
        assertMalformed "3014 020100 ${ALG_ID_PREFIX_HEX}11 0402 3000" // 'both' SEQUENCE with nothing in it
    }

    @Test
    void testToPublicKeyWithWrongMaterialLength() {
        try {
            MlDsaAlgorithm.ML_DSA_44.toPublicKey(new byte[10], null)
            fail()
        } catch (InvalidKeyException expected) {
            assertTrue expected.getMessage().contains('expected 1312 bytes')
        }
    }

    @Test
    void testToPrivateKeyWithWrongSeedLength() {
        try {
            MlDsaAlgorithm.ML_DSA_44.toPrivateKey(new byte[31], null)
            fail()
        } catch (InvalidKeyException expected) {
            assertTrue expected.getMessage().contains('requires 32 bytes')
        }
    }

    @Test
    void testToPrivateKeyWithExplicitProvider() {
        Provider bc = Providers.findBouncyCastle()
        assertNotNull bc // BouncyCastle is always in the test classpath
        PrivateKey key = MlDsaAlgorithm.ML_DSA_44.toPrivateKey(hex(seedHex()), bc)
        assertNotNull key
    }

    @Test
    void testToPrivateKeyWithExplicitProviderWithoutMlDsa() {
        Provider provider = Security.getProvider('SunJCE') // exists on all JDKs, has no ML-DSA support
        assertNotNull provider
        try {
            MlDsaAlgorithm.ML_DSA_44.toPrivateKey(hex(seedHex()), provider)
            fail()
        } catch (RuntimeException expected) { // no fallback occurs when a provider was explicitly specified
            assertNotNull expected
        }
    }

    @Test
    void testGeneratePrivateFallback() { // primary provider fails, fallback succeeds
        Provider broken = Security.getProvider('SunJCE')
        Provider bc = Providers.findBouncyCastle()
        PrivateKey key = MlDsaAlgorithm.ML_DSA_44.generatePrivate(seedP8(), broken, bc)
        assertNotNull key
    }
}
