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
import io.jsonwebtoken.impl.lang.Function;
import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.lang.Collections;
import io.jsonwebtoken.lang.Strings;
import io.jsonwebtoken.security.InvalidKeyException;
import io.jsonwebtoken.security.KeyException;
import io.jsonwebtoken.security.KeyLengthSupplier;
import io.jsonwebtoken.security.KeyPairBuilder;

import java.security.Key;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.Map;

public class EdwardsCurve extends AbstractCurve implements KeyLengthSupplier {

    private static final String OID_PREFIX = "1.3.101.";

    // ASN.1-encoded edwards keys have this exact sequence identifying the type of key that follows.  The trailing
    // byte is the exact edwards curve subsection OID terminal node id.
    private static final byte[] ASN1_OID_PREFIX = new byte[]{0x06, 0x03, 0x2B, 0x65};

    private static final Function<Key, String> CURVE_NAME_FINDER = new NamedParameterSpecValueFinder();

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
            int subcategoryId = curve.ASN1_OID[curve.ASN1_OID.length - 1];
            BY_OID_TERMINAL_NODE.put(subcategoryId, curve);
            REGISTRY.put(curve.getId(), curve);
            REGISTRY.put(curve.OID, curve); // add OID as an alias for alg/id lookups
        }
    }

    private static byte[] publicKeyAsn1Prefix(int byteLength, byte[] ASN1_OID) {
        return Bytes.concat(
                new byte[]{
                        0x30, (byte) (byteLength + 10),
                        0x30, 0x05}, // ASN.1 SEQUENCE of 5 bytes to follow (i.e. the OID)
                ASN1_OID,
                new byte[]{
                        0x03,
                        (byte) (byteLength + 1),
                        0x00}
        );
    }

    private static byte[] privateKeyPkcs8Prefix(int byteLength, byte[] ASN1_OID, boolean ber) {

        byte[] keyPrefix = ber ?
                new byte[]{0x04, (byte) (byteLength + 2), 0x04, (byte) byteLength} : // correct
                new byte[]{0x04, (byte) byteLength}; // https://bugs.openjdk.org/browse/JDK-8213363

        return Bytes.concat(
                new byte[]{
                        0x30,
                        (byte) (5 + ASN1_OID.length + keyPrefix.length + byteLength),
                        0x02, 0x01, 0x00, // encoding version 1 (integer, 1 byte, value 0)
                        0x30, 0x05}, // ASN.1 SEQUENCE of 5 bytes to follow (i.e. the OID)
                ASN1_OID,
                keyPrefix
        );
    }

    private final String OID;

    /**
     * The byte sequence within an ASN.1-encoded key that indicates an Edwards curve encoded key follows. ASN.1 (hex)
     * notation:
     * <pre>
     * 06 03       ;   OBJECT IDENTIFIER (3 bytes long)
     * |  2B 65 $I ;     "1.3.101.$I" for Edwards alg OID, where $I = 6E, 6F, 70, or 71 (decimal 110, 111, 112, or 113)
     * </pre>
     */
    final byte[] ASN1_OID;

    private final int keyBitLength;

    private final int encodedKeyByteLength;

    /**
     * X.509 (ASN.1) encoding of a public key associated with this curve as a prefix (that is, <em>without</em> the
     * actual encoded key material at the end). Appending the public key material directly to the end of this value
     * results in a complete X.509 (ASN.1) encoded public key.  ASN.1 (hex) notation:
     * <pre>
     * 30 $M               ; ASN.1 SEQUENCE ($M bytes long), where $M = encodedKeyByteLength + 10
     *    30 05            ;   ASN.1 SEQUENCE (5 bytes long)
     *       06 03         ;     OBJECT IDENTIFIER (3 bytes long)
     *          2B 65 $I   ;       "1.3.101.$I" for Edwards alg OID, where $I = 6E, 6F, 70, or 71 (110, 111, 112, or 113 decimal)
     *    03 $S            ;   ASN.1 BIT STRING ($S bytes long), where $S = encodedKeyByteLength + 1
     *       00            ;     ASN.1 bit string marker indicating zero unused bits at the end of the bit string
     *       XX XX XX ...  ;     encoded key material (not included in this PREFIX byte array variable)
     * </pre>
     */
    private final byte[] PUBLIC_KEY_ASN1_PREFIX; // https://www.rfc-editor.org/rfc/rfc5280#section-4.1.2.7

    /**
     * PKCS8 (ASN.1) Version 1 encoding of a private key associated with this curve, as a prefix (that is,
     * <em>without</em> actual encoded key material at the end). Appending the private key material directly to the
     * end of this value results in a complete PKCS8 (ASN.1) V1 encoded private key.  ASN.1 (hex) notation:
     * <pre>
     * 30 $M                  ; ASN.1 SEQUENCE ($M bytes long), where $M = encodedKeyByteLength + 14
     *    02 01               ;   ASN.1 INTEGER (1 byte long)
     *       00               ;     zero (private key encoding version V1)
     *    30 05               ;   ASN.1 SEQUENCE (5 bytes long)
     *       06 03            ;     OBJECT IDENTIFIER (3 bytes long). This is the edwards algorithm ID.
     *          2B 65 $I      ;       "1.3.101.$I" for Edwards alg OID, where $I = 6E, 6F, 70, or 71 (110, 111, 112, or 113 decimal)
     *    04 $B               ;   ASN.1 SEQUENCE ($B bytes long, where $B = encodedKeyByteLength + 2
     *       04 $K            ;     ASN.1 SEQUENCE ($K bytes long), where $K = encodedKeyByteLength
     *          XX XX XX ...  ;       encoded key material (not included in this PREFIX byte array variable)
     * </pre>
     */
    private final byte[] PRIVATE_KEY_ASN1_PREFIX;
    private final byte[] PRIVATE_KEY_JDK11_PREFIX; // https://bugs.openjdk.org/browse/JDK-8213363

    /**
     * {@code true} IFF the curve is used for digital signatures, {@code false} if used for key agreement
     */
    private final boolean signatureCurve;

    EdwardsCurve(final String id, int oidTerminalNode) {
        super(id, id);

        if (oidTerminalNode < 110 || oidTerminalNode > 113) {
            String msg = "Invalid Edwards Curve ASN.1 OID terminal node value";
            throw new IllegalArgumentException(msg);
        }

        // OIDs (with terminal node IDs) defined here: https://www.rfc-editor.org/rfc/rfc8410#section-3
        // X25519 (oid 1.3.101.110) has 255 bytes per https://www.rfc-editor.org/rfc/rfc7748.html#section-5 "Here, the "bits" parameter should be set to 255 for X25519 and 448 for X448"
        // X448 (oid 1.3.101.111) have 448 bits per https://www.rfc-editor.org/rfc/rfc7748.html#section-5
        // Ed25519 (oid 1.3.101.112) has 255 bits per https://www.rfc-editor.org/rfc/rfc8032#section-5.1
        // Ed448 (oid 1.3.101.113) has 456 (448 + 8) bits per https://www.rfc-editor.org/rfc/rfc8032#section-5.2
        this.keyBitLength = oidTerminalNode % 2 == 0 ? 255 : 448;
        int encodingBitLen = oidTerminalNode == 113 ?
                this.keyBitLength + Byte.SIZE : // https://www.rfc-editor.org/rfc/rfc8032#section-5.2.2
                this.keyBitLength;
        this.encodedKeyByteLength = Bytes.length(encodingBitLen);

        this.OID = OID_PREFIX + oidTerminalNode;
        this.signatureCurve = (oidTerminalNode == 112 || oidTerminalNode == 113);
        byte[] suffix = new byte[]{(byte) oidTerminalNode};
        this.ASN1_OID = Bytes.concat(ASN1_OID_PREFIX, suffix);

        this.PUBLIC_KEY_ASN1_PREFIX = publicKeyAsn1Prefix(this.encodedKeyByteLength, this.ASN1_OID);
        this.PRIVATE_KEY_ASN1_PREFIX = privateKeyPkcs8Prefix(this.encodedKeyByteLength, this.ASN1_OID, true);
        this.PRIVATE_KEY_JDK11_PREFIX = privateKeyPkcs8Prefix(this.encodedKeyByteLength, this.ASN1_OID, false);
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
            String msg = "Invalid " + getId() + " ASN.1 encoding: " + t.getMessage();
            throw new InvalidKeyException(msg, t);
        }
    }

    /**
     * Parses the ASN.1-encoding of the specified key
     *
     * @param key the Edwards curve key
     * @return the key value, encoded according to <a href="https://www.rfc-editor.org/rfc/rfc8032">RFC 8032</a>
     * @throws RuntimeException if the key's encoded bytes do not reflect a validly ASN.1-encoded edwards key
     */
    protected byte[] doGetKeyMaterial(Key key) {
        byte[] encoded = KeysBridge.getEncoded(key);
        int i = Bytes.indexOf(encoded, ASN1_OID);
        Assert.gt(i, -1, "Missing or incorrect algorithm OID.");
        i = i + ASN1_OID.length;
        int keyLen = 0;
        if (encoded[i] == 0x05) { // NULL terminator, next should be zero byte indicator
            int unusedBytes = encoded[++i];
            Assert.eq(unusedBytes, 0, "OID NULL terminator should indicate zero unused bytes.");
            i++;
        }
        if (encoded[i] == 0x03) { // ASN.1 bit stream, Public Key
            i++;
            keyLen = encoded[i++];
            int unusedBytes = encoded[i++];
            Assert.eq(unusedBytes, 0, "BIT STREAM should not indicate unused bytes.");
            keyLen--;
        } else if (encoded[i] == 0x04) { // ASN.1 octet sequence, Private Key.  Key length follows as next byte.
            i++;
            keyLen = encoded[i++];
            if (encoded[i] == 0x04) { // ASN.1 octet sequence, key length follows as next byte.
                i++; // skip sequence marker
                keyLen = encoded[i++]; // next byte is length
            }
        }
        Assert.eq(keyLen, this.encodedKeyByteLength, "Invalid key length.");
        byte[] result = Arrays.copyOfRange(encoded, i, i + keyLen);
        keyLen = Bytes.length(result);
        Assert.eq(keyLen, this.encodedKeyByteLength, "Invalid key length.");
        return result;
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
        final byte[] encoded = Bytes.concat(this.PUBLIC_KEY_ASN1_PREFIX, x);
        final X509EncodedKeySpec spec = new X509EncodedKeySpec(encoded);
        JcaTemplate template = new JcaTemplate(getJcaName(), provider);
        return template.generatePublic(spec);
    }

    KeySpec privateKeySpec(byte[] d, boolean standard) {
        byte[] prefix = standard ? this.PRIVATE_KEY_ASN1_PREFIX : this.PRIVATE_KEY_JDK11_PREFIX;
        byte[] encoded = Bytes.concat(prefix, d);
        return new PKCS8EncodedKeySpec(encoded);
    }

    public PrivateKey toPrivateKey(final byte[] d, Provider provider) {
        assertLength(d, false);
        KeySpec spec = privateKeySpec(d, true);
        JcaTemplate template = new JcaTemplate(getJcaName(), provider);
        return template.generatePrivate(spec);
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
    public KeyPairBuilder keyPair() {
        return new DefaultKeyPairBuilder(getJcaName(), this.keyBitLength);
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

        // try to perform oid and/or length checks:
        byte[] encoded = KeysBridge.findEncoded(key);

        if (curve == null && !Bytes.isEmpty(encoded)) { // Try to find the Key ASN.1 algorithm OID:
            int oidTerminalNode = findOidTerminalNode(encoded);
            curve = BY_OID_TERMINAL_NODE.get(oidTerminalNode);
        }
        if (curve != null && !Bytes.isEmpty(encoded)) {
            // found a curve, and we have encoded bytes, let's make sure that the encoding represents
            // the correct key length:
            try {
                curve.getKeyMaterial(key);
            } catch (Throwable ignored) {
                curve = null; // key length is invalid for its indicated curve, not a match
            }
        }

        //TODO: check if key exists on discovered curve via equation

        return curve;
    }

    @Override
    public boolean contains(Key key) {
        EdwardsCurve curve = findByKey(key);
        return curve.equals(this);
    }

    private static int findOidTerminalNode(byte[] encoded) {
        int index = Bytes.indexOf(encoded, ASN1_OID_PREFIX);
        if (index > -1) {
            index = index + ASN1_OID_PREFIX.length;
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
            String msg = "Unrecognized Edwards Curve key: [" + KeysBridge.toString(key) + "]";
            throw new InvalidKeyException(msg);
        }
        //TODO: assert key exists on discovered curve via equation
        return curve;
    }

    @SuppressWarnings("UnusedReturnValue")
    static <K extends Key> K assertEdwards(K key) {
        forKey(key); // will throw UnsupportedKeyException if the key is not an Edwards key
        return key;
    }
}
