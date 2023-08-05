/*
 * Copyright © 2023 jsonwebtoken.io
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
import io.jsonwebtoken.impl.lang.CheckedSupplier;
import io.jsonwebtoken.impl.lang.Conditions;
import io.jsonwebtoken.impl.lang.Function;
import io.jsonwebtoken.impl.lang.Functions;
import io.jsonwebtoken.impl.lang.OptionalCtorInvoker;
import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.lang.Collections;
import io.jsonwebtoken.lang.Strings;
import io.jsonwebtoken.security.InvalidKeyException;
import io.jsonwebtoken.security.KeyException;
import io.jsonwebtoken.security.KeyLengthSupplier;
import io.jsonwebtoken.security.KeyPairBuilder;
import io.jsonwebtoken.security.UnsupportedKeyException;

import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.Map;

public class EdwardsCurve extends DefaultCurve implements KeyLengthSupplier {

    private static final String OID_PREFIX = "1.3.101.";

    // DER-encoded edwards keys have this exact sequence identifying the type of key that follows.  The trailing
    // byte is the exact edwards curve subsection OID terminal node id.
    private static final byte[] DER_OID_PREFIX = new byte[]{0x06, 0x03, 0x2B, 0x65};

    private static final String NAMED_PARAM_SPEC_FQCN = "java.security.spec.NamedParameterSpec"; // JDK >= 11
    private static final String XEC_PRIV_KEY_SPEC_FQCN = "java.security.spec.XECPrivateKeySpec"; // JDK >= 11
    private static final String EDEC_PRIV_KEY_SPEC_FQCN = "java.security.spec.EdECPrivateKeySpec"; // JDK >= 15

    private static final Function<Key, String> CURVE_NAME_FINDER = new NamedParameterSpecValueFinder();
    private static final OptionalCtorInvoker<AlgorithmParameterSpec> NAMED_PARAM_SPEC_CTOR =
            new OptionalCtorInvoker<>(NAMED_PARAM_SPEC_FQCN, String.class);
    static final OptionalCtorInvoker<KeySpec> XEC_PRIV_KEY_SPEC_CTOR =
            new OptionalCtorInvoker<>(XEC_PRIV_KEY_SPEC_FQCN, AlgorithmParameterSpec.class, byte[].class);
    static final OptionalCtorInvoker<KeySpec> EDEC_PRIV_KEY_SPEC_CTOR =
            new OptionalCtorInvoker<>(EDEC_PRIV_KEY_SPEC_FQCN, NAMED_PARAM_SPEC_FQCN, byte[].class);

    public static final EdwardsCurve X25519 = new EdwardsCurve("X25519", 110); // Requires JDK >= 11 or BC
    public static final EdwardsCurve X448 = new EdwardsCurve("X448", 111); // Requires JDK >= 11 or BC
    public static final EdwardsCurve Ed25519 = new EdwardsCurve("Ed25519", 112); // Requires JDK >= 15 or BC
    public static final EdwardsCurve Ed448 = new EdwardsCurve("Ed448", 113); // Requires JDK >= 15 or BC

    public static final Collection<EdwardsCurve> VALUES = Collections.of(X25519, X448, Ed25519, Ed448);

    private static final Map<String, EdwardsCurve> REGISTRY;

    private static final Map<Integer, EdwardsCurve> BY_OID_TERMINAL_NODE;

    static {
        REGISTRY = new LinkedHashMap<>(8);
        BY_OID_TERMINAL_NODE = new LinkedHashMap<>(4);
        for (EdwardsCurve curve : VALUES) {
            int subcategoryId = curve.DER_OID[curve.DER_OID.length - 1];
            BY_OID_TERMINAL_NODE.put(subcategoryId, curve);
            REGISTRY.put(curve.getId(), curve);
            REGISTRY.put(curve.OID, curve); // add OID as an alias for alg/id lookups
        }
    }

    private final String OID;

    /**
     * The byte sequence within an DER-encoded key that indicates an Edwards curve encoded key follows. DER (hex)
     * notation:
     * <pre>
     * 06 03       ;   OBJECT IDENTIFIER (3 bytes long)
     * |  2B 65 $I ;     "1.3.101.$I" for Edwards alg OID, where $I = 6E, 6F, 70, or 71 (decimal 110, 111, 112, or 113)
     * </pre>
     */
    final byte[] DER_OID;

    private final int keyBitLength;

    private final int KEY_PAIR_GENERATOR_BIT_LENGTH;

    private final int encodedKeyByteLength;

    /**
     * X.509 (DER) encoding of a public key associated with this curve as a prefix (that is, <em>without</em> the
     * actual encoded key material at the end). Appending the public key material directly to the end of this value
     * results in a complete X.509 (DER) encoded public key.  DER (hex) notation:
     * <pre>
     * 30 $M               ; DER SEQUENCE ($M bytes long), where $M = encodedKeyByteLength + 10
     *    30 05            ;   DER SEQUENCE (5 bytes long)
     *       06 03         ;     OBJECT IDENTIFIER (3 bytes long)
     *          2B 65 $I   ;       "1.3.101.$I" for Edwards alg OID, where $I = 6E, 6F, 70, or 71 (110, 111, 112, or 113 decimal)
     *    03 $S            ;   DER BIT STRING ($S bytes long), where $S = encodedKeyByteLength + 1
     *       00            ;     DER bit string marker indicating zero unused bits at the end of the bit string
     *       XX XX XX ...  ;     encoded key material (not included in this PREFIX byte array variable)
     * </pre>
     */
    private final byte[] PUBLIC_KEY_DER_PREFIX;

    /**
     * PKCS8 (DER) Version 1 encoding of a private key associated with this curve, as a prefix (that is,
     * <em>without</em> actual encoded key material at the end). Appending the private key material directly to the
     * end of this value results in a complete PKCS8 (DER) V1 encoded private key.  DER (hex) notation:
     * <pre>
     * 30 $M                  ; DER SEQUENCE ($M bytes long), where $M = encodedKeyByteLength + 14
     *    02 01               ;   DER INTEGER (1 byte long)
     *       00               ;     zero (private key encoding version V1)
     *    30 05               ;   DER SEQUENCE (5 bytes long)
     *       06 03            ;     OBJECT IDENTIFIER (3 bytes long). This is the edwards algorithm ID.
     *          2B 65 $I      ;       "1.3.101.$I" for Edwards alg OID, where $I = 6E, 6F, 70, or 71 (110, 111, 112, or 113 decimal)
     *    04 $B               ;   DER SEQUENCE ($B bytes long, where $B = encodedKeyByteLength + 2
     *       04 $K            ;     DER SEQUENCE ($K bytes long), where $K = encodedKeyByteLength
     *          XX XX XX ...  ;       encoded key material (not included in this PREFIX byte array variable)
     * </pre>
     */
    private final byte[] PRIVATE_KEY_DER_PREFIX;

    private final AlgorithmParameterSpec NAMED_PARAMETER_SPEC; // null on <= JDK 10

    private final Function<byte[], KeySpec> PRIVATE_KEY_SPEC_FACTORY;

    /**
     * {@code true} IFF the curve is used for digital signatures, {@code false} if used for key agreement
     */
    private final boolean signatureCurve;

    EdwardsCurve(final String id, int oidTerminalNode) {
        super(id, id, // JWT ID and JCA name happen to be identical
                // fall back to BouncyCastle if < JDK 11 (for XDH curves) or < JDK 15 (for EdDSA curves) if necessary:
                Providers.findBouncyCastle(Conditions.notExists(new CheckedSupplier<KeyPairGenerator>() {
                    @Override
                    public KeyPairGenerator get() throws Exception {
                        return KeyPairGenerator.getInstance(id);
                    }
                })));

        // OIDs (with terminal node IDs) defined here: https://www.rfc-editor.org/rfc/rfc8410#section-3
        // X25519 (oid 1.3.101.110) and X448 (oid 1.3.101.111) have 256 bits
        // Ed25519 (oid 1.3.101.112) has 256 bits
        // Ed448 (oid 1.3.101.113) has 456 (448 + 8) bits
        // See https://www.rfc-editor.org/rfc/rfc8032
        switch (oidTerminalNode) {
            case 110:
            case 112:
                this.keyBitLength = 256;
                break;
            case 111:
                this.keyBitLength = 448;
                break;
            case 113:
                this.keyBitLength = 448 + Byte.SIZE;
                break;
            default:
                String msg = "Invalid Edwards Curve ASN.1 OID terminal node value";
                throw new IllegalArgumentException(msg);
        }

        this.OID = OID_PREFIX + oidTerminalNode;
        this.signatureCurve = (oidTerminalNode == 112 || oidTerminalNode == 113);
        byte[] suffix = new byte[]{(byte) oidTerminalNode};
        this.DER_OID = Bytes.concat(DER_OID_PREFIX, suffix);
        this.encodedKeyByteLength = (this.keyBitLength + 7) / 8;

        this.PUBLIC_KEY_DER_PREFIX = Bytes.concat(
                new byte[]{
                        0x30, (byte) (this.encodedKeyByteLength + 10),
                        0x30, 0x05}, // DER SEQUENCE of 5 bytes to follow (i.e. the OID)
                this.DER_OID,
                new byte[]{
                        0x03,
                        (byte) (this.encodedKeyByteLength + 1),
                        0x00}
        );

        byte[] keyPrefix = new byte[]{
                0x04, (byte) (this.encodedKeyByteLength + 2),
                0x04, (byte) this.encodedKeyByteLength};

        this.PRIVATE_KEY_DER_PREFIX = Bytes.concat(
                new byte[]{
                        0x30,
                        (byte) (this.encodedKeyByteLength + 10 + keyPrefix.length),
                        0x02, 0x01, 0x00, // encoding version 1 (integer, 1 byte, value 0)
                        0x30, 0x05}, // DER SEQUENCE of 5 bytes to follow (i.e. the OID)
                this.DER_OID,
                keyPrefix
        );

        this.NAMED_PARAMETER_SPEC = NAMED_PARAM_SPEC_CTOR.apply(id); // null on <= JDK 10
        Function<byte[], KeySpec> paramKeySpecFn = paramKeySpecFactory(NAMED_PARAMETER_SPEC, signatureCurve);
        Function<byte[], KeySpec> pkcs8KeySpecFn = new Pkcs8KeySpecFactory(this.PRIVATE_KEY_DER_PREFIX);
        // prefer the JDK KeySpec classes first, and fall back to PKCS8 encoding if unavailable:
        this.PRIVATE_KEY_SPEC_FACTORY = Functions.firstResult(paramKeySpecFn, pkcs8KeySpecFn);

        // The Sun CE KeyPairGenerator implementation that we'll use to derive PublicKeys with is problematic here:
        //
        // [RFC 7748](https://www.rfc-editor.org/rfc/rfc7748) is clear that X25519 keys are 32 bytes (256 bits) and
        // X448 keys are 56 bytes (448 bits); see the test vectors in
        // [RFC 7748, Section 5.2](https://www.rfc-editor.org/rfc/rfc7748#section-5.2).
        //
        // Additionally [RFC 8032, Section 1](https://www.rfc-editor.org/rfc/rfc8032#section-1) is clear that
        // Ed25519 keys are 32 bytes (256 bits) and Ed448 keys are 57 bytes (456 bits).
        //
        // HOWEVER:
        //
        // The JDK KeyPairGenerator#initialize(keysize, random) method that we use below ONLY accepts
        // values of '255' and '448', which clearly are `keysize`s that do not match the RFC mandatory lengths.
        // The Sun CE implementation:
        //     https://github.com/AdoptOpenJDK/openjdk-jdk15/blob/4a588d89f01a650d90432cc14697a5a2ae2c97d3/src/jdk.crypto.ec/share/classes/sun/security/ec/ed/EdDSAParameters.java#L252-L297
        //
        // (see the two `int bits = 255` and `int bits = 448` lines).
        //
        // It is strange that the JDK implementation does not match the RFC-specified key length values.
        // As such, we 'normalize' our curve's (RFC-correct) key bit length to values that the Sun CE
        // (and also BouncyCastle) will recognize:
        this.KEY_PAIR_GENERATOR_BIT_LENGTH = this.keyBitLength >= 448 ? 448 : 255;
    }

    // visible for testing
    protected static Function<byte[], KeySpec> paramKeySpecFactory(AlgorithmParameterSpec spec, boolean signatureCurve) {
        if (spec == null) {
            return Functions.forNull();
        }
        return new ParameterizedKeySpecFactory(spec, signatureCurve ? EDEC_PRIV_KEY_SPEC_CTOR : XEC_PRIV_KEY_SPEC_CTOR);
    }

    @Override
    public int getKeyBitLength() {
        return this.keyBitLength;
    }

    public byte[] getKeyMaterial(Key key) {
        try {
            return doGetKeyMaterial(key); // can throw assertion and ArrayIndexOutOfBound exception on invalid input
        } catch (Throwable t) {
            if (t instanceof KeyException) { //propagate
                throw (KeyException) t;
            }
            String msg = "Invalid " + getId() + " DER encoding: " + t.getMessage();
            throw new InvalidKeyException(msg, t);
        }
    }

    /**
     * Parses the DER-encoding of the specified key
     *
     * @param key the Edwards curve key
     * @return the key value, encoded according to <a href="https://www.rfc-editor.org/rfc/rfc8032">RFC 8032</a>
     * @throws RuntimeException if the key's encoded bytes do not reflect a validly DER-encoded edwards key
     */
    protected byte[] doGetKeyMaterial(Key key) {
        byte[] encoded = KeysBridge.getEncoded(key);
        int i = Bytes.indexOf(encoded, DER_OID);
        Assert.gt(i, -1, "Missing or incorrect algorithm OID.");
        i = i + DER_OID.length;
        int keyLen = 0;
        if (encoded[i] == 0x05) { // NULL terminator, next should be zero byte indicator
            int unusedBytes = encoded[++i];
            Assert.eq(0, unusedBytes, "OID NULL terminator should indicate zero unused bytes.");
            i++;
        }
        if (encoded[i] == 0x03) { // DER bit stream, Public Key
            i++;
            keyLen = encoded[i++];
            int unusedBytes = encoded[i++];
            Assert.eq(0, unusedBytes, "BIT STREAM should not indicate unused bytes.");
            keyLen--;
        } else if (encoded[i] == 0x04) { // DER octet sequence, Private Key.  Key length follows as next byte.
            i++;
            keyLen = encoded[i++];
            if (encoded[i] == 0x04) { // DER octet sequence, key length follows as next byte.
                i++; // skip sequence marker
                keyLen = encoded[i++]; // next byte is length
            }
        }
        Assert.eq(this.encodedKeyByteLength, keyLen, "Invalid key length.");
        byte[] result = Arrays.copyOfRange(encoded, i, i + keyLen);
        keyLen = Bytes.length(result);
        Assert.eq(this.encodedKeyByteLength, keyLen, "Invalid key length.");
        return result;
    }

    protected Provider fallback(Provider provider) {
        if (provider == null) {
            provider = getProvider();
        }
        return provider;
    }

    private void assertLength(byte[] raw, boolean isPublic) {
        int len = Bytes.length(raw);
        if (len != this.encodedKeyByteLength) {
            String msg = "Invalid " + getId() + " encoded " + (isPublic ? "PublicKey" : "PrivateKey") +
                    " length. Should be " + Bytes.bytesMsg(this.encodedKeyByteLength) + ", found " +
                    Bytes.bytesMsg(len) + ".";
            throw new InvalidKeyException(msg);
        }
    }

    public PublicKey toPublicKey(byte[] x, Provider provider) {
        assertLength(x, true);
        final byte[] encoded = Bytes.concat(this.PUBLIC_KEY_DER_PREFIX, x);
        final X509EncodedKeySpec spec = new X509EncodedKeySpec(encoded);
        JcaTemplate template = new JcaTemplate(getJcaName(), fallback(provider));
        return template.withKeyFactory(new CheckedFunction<KeyFactory, PublicKey>() {
            @Override
            public PublicKey apply(KeyFactory keyFactory) throws Exception {
                return keyFactory.generatePublic(spec);
            }
        });
    }

    public PrivateKey toPrivateKey(byte[] d, Provider provider) {
        assertLength(d, false);
        final KeySpec spec = this.PRIVATE_KEY_SPEC_FACTORY.apply(d);
        JcaTemplate template = new JcaTemplate(getJcaName(), fallback(provider));
        return template.withKeyFactory(new CheckedFunction<KeyFactory, PrivateKey>() {
            @Override
            public PrivateKey apply(KeyFactory keyFactory) throws Exception {
                return keyFactory.generatePrivate(spec);
            }
        });
    }

    /**
     * Returns {@code true} if this curve is used to compute signatures, {@code false} if used for key agreement.
     *
     * @return {@code true} if this curve is used to compute signatures, {@code false} if used for key agreement.
     */
    public boolean isSignatureCurve() {
        return this.signatureCurve;
    }

    @Override
    public KeyPairBuilder keyPairBuilder() {
        return new DefaultKeyPairBuilder(getJcaName(), KEY_PAIR_GENERATOR_BIT_LENGTH).provider(getProvider());
    }

    public static boolean isEdwards(Key key) {
        if (key == null) {
            return false;
        }
        String alg = Strings.clean(key.getAlgorithm());
        return "EdDSA".equals(alg) || "XDH".equals(alg) || findByKey(key) != null;
    }

    /**
     * Computes the PublicKey associated with the specified Edwards-curve PrivateKey.
     *
     * @param pk the Edwards-curve {@code PrivateKey} to inspect.
     * @return the PublicKey associated with the specified Edwards-curve PrivateKey.
     * @throws KeyException if the PrivateKey is not an Edwards-curve key or unable to access the PrivateKey's
     *                      material.
     */
    public static PublicKey derivePublic(PrivateKey pk) throws KeyException {
        return EdwardsPublicKeyDeriver.INSTANCE.apply(pk);
    }

    public static EdwardsCurve findById(String id) {
        return REGISTRY.get(id);
    }

    public static EdwardsCurve findByKey(Key key) {
        if (key == null) {
            return null;
        }

        String alg = key.getAlgorithm();
        EdwardsCurve curve = findById(alg); // try constant time lookup first
        if (curve == null) { // Fall back to JDK 11+ NamedParameterSpec access if possible
            alg = CURVE_NAME_FINDER.apply(key);
            curve = findById(alg);
        }
        if (curve == null) { // Fall back to key encoding if possible:
            // Try to find the Key DER algorithm OID:
            byte[] encoded = KeysBridge.findEncoded(key);
            if (!Bytes.isEmpty(encoded)) {
                int oidTerminalNode = findOidTerminalNode(encoded);
                curve = BY_OID_TERMINAL_NODE.get(oidTerminalNode);
            }
        }

        //TODO: check if key exists on discovered curve via equation

        return curve;
    }

    private static int findOidTerminalNode(byte[] encoded) {
        int index = Bytes.indexOf(encoded, DER_OID_PREFIX);
        if (index > -1) {
            index = index + DER_OID_PREFIX.length;
            if (index < encoded.length) {
                return encoded[index];
            }
        }
        return -1;
    }

    public static EdwardsCurve forKey(Key key) {
        Assert.notNull(key, "Key cannot be null.");
        EdwardsCurve curve = findByKey(key);
        if (curve == null) {
            String msg = key.getClass().getName() + " with algorithm '" + key.getAlgorithm() +
                    "' is not a recognized Edwards Curve key.";
            throw new UnsupportedKeyException(msg);
        }
        //TODO: assert key exists on discovered curve via equation
        return curve;
    }

    @SuppressWarnings("UnusedReturnValue")
    static <K extends Key> K assertEdwards(K key) {
        forKey(key); // will throw UnsupportedKeyException if the key is not an Edwards key
        return key;
    }

    private static final class Pkcs8KeySpecFactory implements Function<byte[], KeySpec> {
        private final byte[] PREFIX;

        private Pkcs8KeySpecFactory(byte[] pkcs8EncodedKeyPrefix) {
            this.PREFIX = Assert.notEmpty(pkcs8EncodedKeyPrefix, "pkcs8EncodedKeyPrefix cannot be null or empty.");
        }

        @Override
        public KeySpec apply(byte[] d) {
            Assert.notEmpty(d, "Key bytes cannot be null or empty.");
            byte[] encoded = Bytes.concat(PREFIX, d);
            return new PKCS8EncodedKeySpec(encoded);
        }
    }

    // visible for testing
    protected static final class ParameterizedKeySpecFactory implements Function<byte[], KeySpec> {

        private final AlgorithmParameterSpec params;

        private final Function<Object, KeySpec> keySpecFactory;

        ParameterizedKeySpecFactory(AlgorithmParameterSpec params, Function<Object, KeySpec> keySpecFactory) {
            this.params = Assert.notNull(params, "AlgorithmParameterSpec cannot be null.");
            this.keySpecFactory = Assert.notNull(keySpecFactory, "KeySpec factory function cannot be null.");
        }

        @Override
        public KeySpec apply(byte[] d) {
            Assert.notEmpty(d, "Key bytes cannot be null or empty.");
            Object[] args = new Object[]{params, d};
            return this.keySpecFactory.apply(args);
        }
    }
}
