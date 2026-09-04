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
package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.impl.lang.Bytes;
import io.jsonwebtoken.impl.lang.CheckedFunction;
import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.lang.Collections;
import io.jsonwebtoken.lang.Strings;
import io.jsonwebtoken.security.InvalidKeyException;
import io.jsonwebtoken.security.KeyPairBuilder;
import io.jsonwebtoken.security.UnsupportedKeyException;

import java.security.Key;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * An ML-DSA (FIPS 204) parameter set as used by the {@code AKP} JWK key type defined in
 * <a href="https://www.rfc-editor.org/rfc/rfc9964.html">RFC 9964</a>.
 *
 * <p>ML-DSA keys have no dedicated {@code java.security.interfaces} type, so this class identifies them the same
 * way {@link EdwardsCurve} identifies Edwards keys: by the key's JCA algorithm name when it is specific enough, and
 * otherwise by the algorithm OID embedded in the key's ASN.1 encoding.  The latter is required because the JDK's
 * {@code SUN} provider reports the generic algorithm name {@code "ML-DSA"} for all three parameter sets, while
 * BouncyCastle reports the specific {@code "ML-DSA-44"}, {@code "ML-DSA-65"} or {@code "ML-DSA-87"} name.</p>
 *
 * @since 0.14.0
 */
final class MlDsaAlgorithm {

    /**
     * Length in bytes of an ML-DSA private key seed, per RFC 9964, Section 6: &quot;For the ML-DSA private keys
     * described in this document, the priv parameter MUST be the seed and MUST have a length of 32 bytes.&quot;
     */
    static final int SEED_LENGTH = 32;

    /**
     * The generic JCA algorithm name reported by the JDK {@code SUN} provider for all ML-DSA parameter sets.
     */
    private static final String GENERIC_JCA_NAME = "ML-DSA";

    /**
     * The first 12 bytes of the ML-DSA ASN.1 AlgorithmIdentifier SEQUENCE, i.e. everything up to (but excluding) the
     * terminal OID node that distinguishes the parameter set.  ASN.1 (hex) notation:
     * <pre>
     * 30 0B          ; ASN.1 SEQUENCE (11 bytes long)
     *    06 09       ;   OBJECT IDENTIFIER (9 bytes long)
     *       60 86 48 01 65 03 04 03 $I ; "2.16.840.1.101.3.4.3.$I", where $I = 17, 18, or 19 for ML-DSA-44/65/87
     * </pre>
     */
    private static final byte[] ALG_ID_PREFIX = new byte[]{
            0x30, 0x0B, 0x06, 0x09, 0x60, (byte) 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03
    };

    /**
     * Number of bytes preceding the PKCS#8 {@code privateKey} OCTET STRING, not counting the outer SEQUENCE tag and
     * length: the 3-byte version INTEGER plus the 13-byte AlgorithmIdentifier.
     */
    private static final int PKCS8_HEADER_LENGTH = 3 + (ALG_ID_PREFIX.length + 1);

    // ML-DSA-PrivateKey CHOICE alternative tags, per the LAMPS ML-DSA certificate specification:
    private static final byte SEED_TAG = (byte) 0x80; // seed [0] IMPLICIT OCTET STRING
    private static final byte OCTET_STRING_TAG = 0x04;
    private static final byte SEQUENCE_TAG = 0x30;

    static final MlDsaAlgorithm ML_DSA_44 = new MlDsaAlgorithm("ML-DSA-44", 17, 1312);
    static final MlDsaAlgorithm ML_DSA_65 = new MlDsaAlgorithm("ML-DSA-65", 18, 1952);
    static final MlDsaAlgorithm ML_DSA_87 = new MlDsaAlgorithm("ML-DSA-87", 19, 2592);

    static final Collection<MlDsaAlgorithm> VALUES = Collections.of(ML_DSA_44, ML_DSA_65, ML_DSA_87);

    private static final Map<String, MlDsaAlgorithm> REGISTRY;
    private static final Map<Integer, MlDsaAlgorithm> BY_OID_TERMINAL_NODE;

    static {
        REGISTRY = new LinkedHashMap<>(6);
        BY_OID_TERMINAL_NODE = new LinkedHashMap<>(3);
        for (MlDsaAlgorithm alg : VALUES) {
            REGISTRY.put(alg.id, alg);
            BY_OID_TERMINAL_NODE.put(alg.oidTerminalNode, alg);
        }
    }

    private final String id;
    private final int oidTerminalNode;
    private final int publicKeyByteLength;

    /**
     * X.509 SubjectPublicKeyInfo prefix for this parameter set, i.e. the complete encoding of a public key
     * <em>without</em> the trailing raw key material.  ASN.1 (hex) notation:
     * <pre>
     * 30 82 $LL $LL          ; ASN.1 SEQUENCE (publicKeyByteLength + 18 bytes long)
     *    30 0B               ;   ASN.1 SEQUENCE (11 bytes long)
     *       06 09 ...        ;     OBJECT IDENTIFIER (the ML-DSA parameter set OID)
     *    03 82 $LL $LL       ;   ASN.1 BIT STRING (publicKeyByteLength + 1 bytes long)
     *       00               ;     zero unused bits at the end of the bit string
     *       XX XX XX ...     ;     raw key material (not included in this prefix)
     * </pre>
     */
    private final byte[] publicKeyAsn1Prefix;

    private MlDsaAlgorithm(String id, int oidTerminalNode, int publicKeyByteLength) {
        this.id = Assert.hasText(id, "id cannot be null or empty.");
        this.oidTerminalNode = oidTerminalNode;
        this.publicKeyByteLength = publicKeyByteLength;
        this.publicKeyAsn1Prefix = publicKeyAsn1Prefix(oidTerminalNode, publicKeyByteLength);
    }

    private static byte[] algorithmIdentifier(int oidTerminalNode) {
        return Bytes.concat(ALG_ID_PREFIX, new byte[]{(byte) oidTerminalNode});
    }

    private static byte[] publicKeyAsn1Prefix(int oidTerminalNode, int publicKeyByteLength) {
        byte[] algId = algorithmIdentifier(oidTerminalNode);
        int bitStringLength = publicKeyByteLength + 1; // + 1 for the 'unused bits' byte
        int sequenceLength = algId.length + 4 + bitStringLength; // 4 = BIT STRING tag + 2 length bytes + unused bits
        return Bytes.concat(
                new byte[]{SEQUENCE_TAG, (byte) 0x82, (byte) (sequenceLength >>> 8), (byte) sequenceLength},
                algId,
                new byte[]{0x03, (byte) 0x82, (byte) (bitStringLength >>> 8), (byte) bitStringLength, 0x00}
        );
    }

    String getId() {
        return this.id;
    }

    int getPublicKeyByteLength() {
        return this.publicKeyByteLength;
    }

    KeyPairBuilder keyPair() {
        return new DefaultKeyPairBuilder(this.id);
    }

    /**
     * Returns the ML-DSA parameter set with the specified RFC 9964 {@code alg} identifier, or {@code null} if the
     * identifier is not a recognized ML-DSA parameter set.
     *
     * @param id the algorithm identifier to look up, e.g. {@code ML-DSA-65}
     * @return the matching parameter set, or {@code null}.
     */
    static MlDsaAlgorithm findById(String id) {
        return id == null ? null : REGISTRY.get(id);
    }

    /**
     * Returns the ML-DSA parameter set represented by the specified key, or {@code null} if the key is not an ML-DSA
     * key or its parameter set cannot be determined.
     *
     * @param key the key to inspect
     * @return the key's ML-DSA parameter set, or {@code null}.
     */
    static MlDsaAlgorithm findByKey(Key key) {
        if (key == null) {
            return null;
        }

        // Providers that name the key by its specific parameter set (e.g. BouncyCastle) allow a constant-time lookup:
        MlDsaAlgorithm alg = findById(Strings.clean(key.getAlgorithm()));
        if (alg != null) {
            return alg;
        }

        // Otherwise fall back to the algorithm OID in the key's ASN.1 encoding.  This is required for the JDK SUN
        // provider, which reports the generic "ML-DSA" name for every parameter set:
        byte[] encoded = KeysBridge.findEncoded(key);
        try {
            if (Bytes.isEmpty(encoded)) {
                return null;
            }
            int index = Bytes.indexOf(encoded, ALG_ID_PREFIX);
            if (index < 0) {
                return null;
            }
            index += ALG_ID_PREFIX.length;
            if (index >= encoded.length) {
                return null;
            }
            return BY_OID_TERMINAL_NODE.get((int) encoded[index]);
        } finally {
            Bytes.clear(encoded);
        }
    }

    /**
     * Returns {@code true} if the specified key is an ML-DSA key, {@code false} otherwise.
     *
     * @param key the key to inspect
     * @return {@code true} if the specified key is an ML-DSA key, {@code false} otherwise.
     */
    static boolean isMlDsa(Key key) {
        if (key == null) {
            return false;
        }
        return GENERIC_JCA_NAME.equals(Strings.clean(key.getAlgorithm())) || findByKey(key) != null;
    }

    /**
     * Returns the ML-DSA parameter set represented by the specified key, throwing {@link InvalidKeyException} if it
     * cannot be determined.
     *
     * @param key the key to inspect
     * @return the key's ML-DSA parameter set.
     * @throws InvalidKeyException if the key is not a recognizable ML-DSA key.
     */
    static MlDsaAlgorithm forKey(Key key) throws InvalidKeyException {
        Assert.notNull(key, "Key cannot be null.");
        MlDsaAlgorithm alg = findByKey(key);
        if (alg == null) {
            String msg = "Unrecognized ML-DSA key: [" + KeysBridge.toString(key) + "]";
            throw new InvalidKeyException(msg);
        }
        return alg;
    }

    /**
     * Asserts that the specified key is a recognizable ML-DSA key, returning it if so.
     *
     * @param key the key to inspect
     * @return the specified key.
     * @throws InvalidKeyException if the key is not a recognizable ML-DSA key.
     */
    @SuppressWarnings("UnusedReturnValue")
    static <K extends Key> K assertMlDsa(K key) throws InvalidKeyException {
        forKey(key); // will throw if the key is not an ML-DSA key
        return key;
    }

    /**
     * Returns the raw FIPS 204 public key material contained in the specified key's X.509 encoding.
     *
     * @param key the public key to inspect
     * @return the key's raw public key material.
     * @throws InvalidKeyException if the key's encoding is unavailable or malformed.
     */
    byte[] getPublicKeyMaterial(PublicKey key) throws InvalidKeyException {
        byte[] encoded = KeysBridge.getEncoded(key);
        int expected = this.publicKeyAsn1Prefix.length + this.publicKeyByteLength;
        if (encoded.length != expected || !Bytes.startsWith(encoded, this.publicKeyAsn1Prefix)) {
            String msg = "Invalid " + this.id + " X.509 encoding for key [" + KeysBridge.toString(key) + "]: " +
                    "expected " + expected + " bytes with a standard " + this.id + " SubjectPublicKeyInfo prefix, " +
                    "but found " + encoded.length + " bytes.";
            throw new InvalidKeyException(msg);
        }
        byte[] material = new byte[this.publicKeyByteLength];
        System.arraycopy(encoded, this.publicKeyAsn1Prefix.length, material, 0, this.publicKeyByteLength);
        return material;
    }

    /**
     * Returns the 32-byte private key seed contained in the specified key's PKCS#8 encoding.
     *
     * <p>RFC 9964 requires the {@code priv} JWK parameter to be the seed, but the PKCS#8 ML-DSA private key format
     * is a CHOICE of {@code seed}, {@code expandedKey} or {@code both}, and not every provider emits a form that
     * retains the seed.  Notably, JDK 24 through 26 emit {@code expandedKey} only, from which the seed cannot be
     * recovered.</p>
     *
     * @param key the private key to inspect
     * @return the key's 32-byte seed.
     * @throws InvalidKeyException if the key's encoding is unavailable, malformed, or does not retain the seed.
     */
    byte[] getSeed(PrivateKey key) throws InvalidKeyException {
        byte[] encoded = KeysBridge.getEncoded(key);
        byte[] seed = findSeed(encoded);
        if (seed == null) {
            String msg = "Unable to obtain the " + this.id + " private key seed required by RFC 9964 from key [" +
                    KeysBridge.toString(key) + "]: its PKCS#8 encoding contains an expanded private key instead of " +
                    "the seed.  A seed-retaining ML-DSA key is required, for example one created from an existing " +
                    "RFC 9964 JWK, or one generated by a provider that preserves the seed.";
            throw new InvalidKeyException(msg);
        }
        return seed;
    }

    /**
     * Locates the 32-byte seed within a PKCS#8 ML-DSA private key encoding, returning {@code null} if the encoding
     * is well-formed but carries only an expanded private key.
     */
    private byte[] findSeed(byte[] encoded) throws InvalidKeyException {
        int i = 0;
        if (encoded.length < 2 || encoded[i++] != SEQUENCE_TAG) {
            throw malformedPkcs8();
        }
        i = skipLength(encoded, i);
        i += PKCS8_HEADER_LENGTH; // version INTEGER + AlgorithmIdentifier SEQUENCE
        if (i >= encoded.length || encoded[i++] != OCTET_STRING_TAG) { // the PKCS#8 privateKey OCTET STRING
            throw malformedPkcs8();
        }
        i = skipLength(encoded, i);
        if (i >= encoded.length) {
            throw malformedPkcs8();
        }

        byte choice = encoded[i++];
        if (choice == SEED_TAG) { // seed [0] IMPLICIT OCTET STRING (SIZE (32))
            return readSeed(encoded, i);
        }
        if (choice == SEQUENCE_TAG) { // both ::= SEQUENCE { seed OCTET STRING, expandedKey OCTET STRING }
            i = skipLength(encoded, i);
            if (i >= encoded.length || encoded[i++] != OCTET_STRING_TAG) {
                throw malformedPkcs8();
            }
            return readSeed(encoded, i);
        }
        if (choice == OCTET_STRING_TAG) { // expandedKey only - the seed is not recoverable
            return null;
        }
        throw malformedPkcs8();
    }

    /**
     * Reads a definite-length seed OCTET STRING whose length byte is at the specified index.
     */
    private byte[] readSeed(byte[] encoded, int index) throws InvalidKeyException {
        if (index >= encoded.length || (encoded[index] & 0xFF) != SEED_LENGTH) {
            throw malformedPkcs8();
        }
        index++;
        if (index + SEED_LENGTH > encoded.length) {
            throw malformedPkcs8();
        }
        byte[] seed = new byte[SEED_LENGTH];
        System.arraycopy(encoded, index, seed, 0, SEED_LENGTH);
        return seed;
    }

    /**
     * Returns the index immediately following the DER definite-length octets beginning at the specified index.
     */
    private int skipLength(byte[] encoded, int index) throws InvalidKeyException {
        if (index >= encoded.length) {
            throw malformedPkcs8();
        }
        int first = encoded[index++] & 0xFF;
        if (first > 0x80) {
            index += (first & 0x7F);
        }
        if (index > encoded.length) {
            throw malformedPkcs8();
        }
        return index;
    }

    private InvalidKeyException malformedPkcs8() {
        return new InvalidKeyException("Malformed " + this.id + " PKCS#8 private key encoding.");
    }

    /**
     * Converts raw FIPS 204 public key material to a {@link PublicKey}.
     *
     * @param material the raw public key material
     * @param provider the JCA provider to use, or {@code null} for the JCA default
     * @return the resulting {@code PublicKey}.
     */
    PublicKey toPublicKey(final byte[] material, Provider provider) {
        if (Bytes.length(material) != this.publicKeyByteLength) {
            String msg = "Invalid " + this.id + " public key length: expected " + this.publicKeyByteLength +
                    " bytes, but found " + Bytes.length(material) + " bytes.";
            throw new InvalidKeyException(msg);
        }
        final byte[] encoded = Bytes.concat(this.publicKeyAsn1Prefix, material);
        JcaTemplate template = new JcaTemplate(this.id, provider);
        return template.withKeyFactory(new CheckedFunction<KeyFactory, PublicKey>() {
            @Override
            public PublicKey apply(KeyFactory keyFactory) throws Exception {
                return keyFactory.generatePublic(new X509EncodedKeySpec(encoded));
            }
        });
    }

    /**
     * Converts a 32-byte private key seed to a {@link PrivateKey}.
     *
     * @param seed     the 32-byte private key seed
     * @param provider the JCA provider to use, or {@code null} for the JCA default
     * @return the resulting {@code PrivateKey}.
     */
    PrivateKey toPrivateKey(final byte[] seed, Provider provider) {
        if (Bytes.length(seed) != SEED_LENGTH) {
            String msg = "Invalid " + this.id + " private key seed length: RFC 9964 requires " + SEED_LENGTH +
                    " bytes, but found " + Bytes.length(seed) + " bytes.";
            throw new InvalidKeyException(msg);
        }
        final byte[] encoded = pkcs8(seed);
        try {
            // The seed CHOICE alternative required by RFC 9964 is not understood by every provider that otherwise
            // supports ML-DSA: the JDK SUN provider only accepts an expanded private key encoding until JDK 27.
            // Because the algorithm itself is available in those JDK versions, JcaTemplate's usual
            // NoSuchAlgorithmException-triggered fallback does not apply, so retry with BouncyCastle explicitly
            // when the caller did not specify a provider and BouncyCastle is available:
            Provider fallback = provider == null ? Providers.findBouncyCastle() : null;
            return generatePrivate(encoded, provider, fallback);
        } finally {
            Bytes.clear(encoded);
        }
    }

    // package-protected visibility for testing:
    PrivateKey generatePrivate(byte[] encoded, Provider provider, Provider fallback) {
        try {
            return generatePrivate(encoded, provider);
        } catch (RuntimeException e) {
            if (fallback == null) {
                throw e;
            }
            return generatePrivate(encoded, fallback);
        }
    }

    private PrivateKey generatePrivate(final byte[] encoded, Provider provider) {
        JcaTemplate template = new JcaTemplate(this.id, provider);
        return template.withKeyFactory(new CheckedFunction<KeyFactory, PrivateKey>() {
            @Override
            public PrivateKey apply(KeyFactory keyFactory) throws Exception {
                return keyFactory.generatePrivate(new PKCS8EncodedKeySpec(encoded));
            }
        });
    }

    /**
     * Returns the PKCS#8 encoding of the specified seed using the {@code seed} CHOICE alternative.  ASN.1 (hex)
     * notation:
     * <pre>
     * 30 34                  ; ASN.1 SEQUENCE (52 bytes long)
     *    02 01 00            ;   ASN.1 INTEGER 0 (PKCS#8 version 1)
     *    30 0B               ;   ASN.1 SEQUENCE (11 bytes long)
     *       06 09 ...        ;     OBJECT IDENTIFIER (the ML-DSA parameter set OID)
     *    04 22               ;   ASN.1 OCTET STRING (34 bytes long)
     *       80 20            ;     [0] IMPLICIT OCTET STRING (32 bytes long)
     *          XX XX XX ...  ;       the seed
     * </pre>
     */
    private byte[] pkcs8(byte[] seed) {
        byte[] algId = algorithmIdentifier(this.oidTerminalNode);
        int privateKeyLength = 2 + SEED_LENGTH; // [0] IMPLICIT tag + length byte + seed
        int sequenceLength = 3 + algId.length + 2 + privateKeyLength;
        return Bytes.concat(
                new byte[]{SEQUENCE_TAG, (byte) sequenceLength, 0x02, 0x01, 0x00},
                algId,
                new byte[]{OCTET_STRING_TAG, (byte) privateKeyLength, SEED_TAG, (byte) SEED_LENGTH},
                seed
        );
    }

    /**
     * Returns the parameter set identified by the specified RFC 9964 {@code alg} value, throwing
     * {@link UnsupportedKeyException} if the value is not a recognized ML-DSA parameter set.
     *
     * @param alg the {@code alg} value to look up
     * @return the matching parameter set.
     */
    static MlDsaAlgorithm forId(String alg) throws UnsupportedKeyException {
        MlDsaAlgorithm found = findById(alg);
        if (found == null) {
            String msg = "Unrecognized AKP JWK 'alg' value '" + alg + "'. RFC 9964 AKP JWKs require an 'alg' value " +
                    "of " + ML_DSA_44.id + ", " + ML_DSA_65.id + " or " + ML_DSA_87.id + ".";
            throw new UnsupportedKeyException(msg);
        }
        return found;
    }

    @Override
    public String toString() {
        return this.id;
    }
}
