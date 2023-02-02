package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.impl.lang.Bytes;
import io.jsonwebtoken.impl.lang.CheckedFunction;
import io.jsonwebtoken.impl.lang.CheckedSupplier;
import io.jsonwebtoken.impl.lang.Conditions;
import io.jsonwebtoken.impl.lang.Function;
import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.lang.Collections;
import io.jsonwebtoken.lang.Strings;
import io.jsonwebtoken.security.InvalidKeyException;
import io.jsonwebtoken.security.KeyException;
import io.jsonwebtoken.security.KeyLengthSupplier;
import io.jsonwebtoken.security.UnsupportedKeyException;

import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
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
    private static final byte[] DER_OID_PREFIX = new byte[]{0x30, 0x05, 0x06, 0x03, 0x2B, 0x65};

    private static final Function<Key, String> CURVE_NAME_FINDER = new NamedParameterSpecValueFinder();

    public static final EdwardsCurve X25519 = new EdwardsCurve("X25519", 110); // >= JDK 11 or BC is needed
    public static final EdwardsCurve X448 = new EdwardsCurve("X448", 111); // >= JDK 11 or BC is needed
    public static final EdwardsCurve Ed25519 = new EdwardsCurve("Ed25519", 112); // >= JDK 15 or BC is needed
    public static final EdwardsCurve Ed448 = new EdwardsCurve("Ed448", 113); // >= JDK 15 or BC is needed

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
     * 30 05          ; DER SEQUENCE (5 bytes long)
     * |  06 03       ;   OBJECT IDENTIFIER (3 bytes long)
     * |  |  2B 65 $I ;     "1.3.101.$I" for Edwards alg OID, where $I = 6E, 6F, 70, or 71 (decimal 110, 111, 112, or 113)
     * </pre>
     */
    final byte[] DER_OID;

    private final int keyBitLength;

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

    /**
     * {@code true} IFF the curve is used for digital signatures, {@code false} if used for key agreement
     */
    private final boolean signatureCurve;

    EdwardsCurve(final String id, int oidTerminalNode) {
        super(id, id, // JWT ID and JCA name happen to be identical
                // fall back to BouncyCastle if >= JDK 11 (for XDH curves) or 15 (for EdDSA curves) if necessary:
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
                new byte[]{0x30, (byte) (this.encodedKeyByteLength + 10)},
                this.DER_OID,
                new byte[]{0x03, (byte) (this.encodedKeyByteLength + 1), 0x00}
        );

        this.PRIVATE_KEY_DER_PREFIX = Bytes.concat(
                new byte[]{0x30, (byte) (this.encodedKeyByteLength + 14),
                        0x02, 0x01, 0x00}, // encoding version 1 (integer, 1 byte, value 0)
                this.DER_OID,
                new byte[]{
                        0x04, (byte) (this.encodedKeyByteLength + 2),
                        0x04, (byte) this.encodedKeyByteLength});
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
        i = i + DER_OID.length;
        int keyLen = 0;
        if (encoded[i] == 0x03) { // DER bit stream, Public Key
            i++;
            keyLen = encoded[i++];
            int unusedBytes = encoded[i++];
            Assert.eq(0, unusedBytes, "BIT STREAM should not indicate unused bytes.");
            keyLen--;
        } else if (encoded[i] == 0x04) { // DER octet sequence, Private Key.  Key length follows as next byte.
            i++;
            keyLen = encoded[i++];
            if (encoded[i++] == 0x04) { // DER octet sequence, key length follows as next byte.
                keyLen = encoded[i++];
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

    private void assertLength(byte[] raw) {
        int len = Bytes.length(raw);
        if (len != this.encodedKeyByteLength) {
            String msg = "Invalid " + getId() + " encoded key length. Should be " +
                    Bytes.bytesMsg(this.encodedKeyByteLength) + ", found " +
                    Bytes.bytesMsg(len) + ".";
            throw new InvalidKeyException(msg);
        }
    }

    public PublicKey toPublicKey(byte[] x, Provider provider) {
        assertLength(x);
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
        assertLength(d);
        final byte[] encoded = Bytes.concat(this.PRIVATE_KEY_DER_PREFIX, d);
        final PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(encoded);
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

    public static boolean isEdwards(Key key) {
        if (key == null) {
            return false;
        }
        String alg = Strings.clean(key.getAlgorithm());
        return "EdDSA".equals(alg) || "XDH".equals(alg) || findByKey(key) != null;
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

        //TODO: assert key exists on curve

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
        return curve;
    }

    @SuppressWarnings("UnusedReturnValue")
    static <K extends Key> K assertEdwards(K key) {
        forKey(key); // will throw UnsupportedKeyException if the key is not an Edwards key
        return key;
    }
}
