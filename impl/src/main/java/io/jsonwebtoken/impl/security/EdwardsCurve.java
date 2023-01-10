package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.impl.lang.Bytes;
import io.jsonwebtoken.impl.lang.CheckedFunction;
import io.jsonwebtoken.impl.lang.CheckedSupplier;
import io.jsonwebtoken.impl.lang.Conditions;
import io.jsonwebtoken.impl.lang.IdRegistry;
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

    public static final EdwardsCurve X25519 = new EdwardsCurve("X25519", 256, 110); // >= JDK 11 or BC is needed
    public static final EdwardsCurve X448 = new EdwardsCurve("X448", 448, 111); // >= JDK 11 or BC is needed
    public static final EdwardsCurve Ed25519 = new EdwardsCurve("Ed25519", 256, 112); // >= JDK 15 or BC is needed
    public static final EdwardsCurve Ed448 = new EdwardsCurve("Ed448", 448, 113); // >= JDK 15 or BC is needed

    public static final Collection<EdwardsCurve> VALUES = Collections.of(X25519, X448, Ed25519, Ed448);

    private static final IdRegistry<EdwardsCurve> REGISTRY;

    private static final Map<Integer, EdwardsCurve> BY_OID_SUBGROUP;

    static {
        REGISTRY = new IdRegistry<>(VALUES);
        BY_OID_SUBGROUP = new LinkedHashMap<>(4);
        for (EdwardsCurve curve : VALUES) {
            int subcategoryId = curve.DER_KEY_OID[curve.DER_KEY_OID.length - 1];
            BY_OID_SUBGROUP.put(subcategoryId, curve);
        }
    }


    // DER-encoded edwards keys have this exact sequence identifying the type of key that follows.  The trailing
    // byte is the exact edwards curve subsection OID group ID
    static final byte[] DER_OID_PREFIX = new byte[]{0x30, 0x05, 0x06, 0x03, 0x2B, 0x65};


    /**
     * The byte sequence within an DER-encoded key that indicates an Edwards curve encoded key follows. DER (hex)
     * notation:
     * <pre>
     * 30 05          ; DER SEQUENCE (5 bytes long)
     * |  06 03       ;   OBJECT IDENTIFIER (3 bytes long)
     * |  |  2B 65 $I ;     "1.3.101.$I" for Edwards alg OID, where $I = 6E, 6F, 70, or 71 (decimal 110, 111, 112, or 113)
     * </pre>
     */
    final byte[] DER_KEY_OID;

    private final int keyBitLength;

    private final int encodedKeyByteLength;

    /**
     * X.509 (DER) encoding of a public key associated with this curve as a prefix (that is, <em>without</em> the
     * actual encoded key material at the end). Appending the public key material directly to the end of this value
     * results in a complete X.509 (DER) encoded public key.  DER (hex) notation:
     * <pre>
     * 30 $M               ; DER SEQUENCE ($M bytes long), where $M = encodedKeyByteLength + 10
     *    30 05            ;   DER SEQUENCE (5 bytes long)
     *       06 03         ;     OBJECT IDENTIFIER (5 bytes long)
     *          2B 65 $I   ;       "1.3.101.$I" for Edwards alg OID, where $I = 6E, 6F, 70, or 71 (110, 111, 112, or 113 decimal)
     *    03 $S            ;   DER BIT STRING ($S bytes long), where $S = encodedKeyByteLength + 1
     *       00            ;     DER bit string marker indicating zero unused bits at the end of the bit string
     *       XX XX ...     ;     encoded key material (not included in this PREFIX byte array variable)
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
     *       06 03            ;     OBJECT IDENTIFIER (5 bytes long). This is the edwards algorithm ID.
     *          2B 65 $I      ;       "1.3.101.$I" for Edwards alg OID, where $I = 6E, 6F, 70, or 71 (110, 111, 112, or 113 decimal)
     *    04 $B               ;   DER SEQUENCE ($B bytes long, where $B = encodedKeyByteLength + 2
     *       04 $K            ;     DER SEQUENCE ($K bytes long), where $K = encodedKeyByteLength
     *          XX XX XX ...  ;       encoded key material (not included in this PREFIX byte array variable)
     * </pre>
     */
    private final byte[] PRIVATE_KEY_DER_PREFIX;

    EdwardsCurve(final String id, final int keyBitLength, int oidSubgroupId) {
        super(id, id, // JWT ID and JCA name happen to be identical
                // fall back to BouncyCastle if >= JDK 11 (for XDH curves) or 15 (for EdDSA curves) if necessary:
                Providers.findBouncyCastle(Conditions.notExists(new CheckedSupplier<KeyPairGenerator>() {
                    @Override
                    public KeyPairGenerator get() throws Exception {
                        return KeyPairGenerator.getInstance(id);
                    }
                })));
        if (keyBitLength != 256 && keyBitLength != 448) {
            throw new IllegalArgumentException("Unsupported Edwards Curve key bit length.");
        }
        this.keyBitLength = keyBitLength;
        if (oidSubgroupId < 110 || oidSubgroupId > 113) { // https://www.rfc-editor.org/rfc/rfc8410#section-3
            String msg = "Invalid Edwards Curve ASN.1 OID subgroup ID";
            throw new IllegalArgumentException(msg);
        }
        byte[] suffix = new byte[]{(byte) oidSubgroupId};
        this.DER_KEY_OID = Bytes.concat(DER_OID_PREFIX, suffix);

        int encodedKeyByteLength = (keyBitLength + 7) / 8;
        if ("Ed448".equalsIgnoreCase(id)) {
            encodedKeyByteLength = encodedKeyByteLength + 1; // https://www.rfc-editor.org/rfc/rfc8032#section-5.2.2
        }
        this.encodedKeyByteLength = encodedKeyByteLength;

        this.PUBLIC_KEY_DER_PREFIX = Bytes.concat(
                new byte[]{0x30, (byte) (this.encodedKeyByteLength + 10)},
                this.DER_KEY_OID,
                new byte[]{0x03, (byte) (this.encodedKeyByteLength + 1), 0x00}
        );

        this.PRIVATE_KEY_DER_PREFIX = Bytes.concat(
                new byte[]{0x30, (byte) (this.encodedKeyByteLength + 14)},
                this.DER_KEY_OID,
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
        } catch (Exception e) {
            if (e instanceof KeyException) { //propagate
                throw (KeyException) e;
            }
            String msg = "Invalid " + getId() + " DER encoding: " + e.getMessage();
            throw new InvalidKeyException(msg, e);
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
        int i = Bytes.indexOf(encoded, DER_KEY_OID);
        i = i + DER_KEY_OID.length;
        int keyLen = 0;
        if (encoded[i] == 0x03) { // DER bit stream, Public Key
            i++;
            keyLen = encoded[i++];
            int unusedBytes = encoded[i++];
            assert unusedBytes == 0; // DER bit stream should not have unused bytes
            keyLen--;
        } else if (encoded[i] == 0x04) { // DER octet sequence, Private Key
            i++;
            keyLen = encoded[i++];
            if (encoded[i++] == 4) {
                keyLen = encoded[i++];
            }
        }
        assert keyLen == encodedKeyByteLength; // RFC encoding requirement
        byte[] result = Arrays.copyOfRange(encoded, i, i + keyLen);
        assert encodedKeyByteLength == Bytes.length(result);
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
                    Bytes.bytesMsg(this.encodedKeyByteLength) + ". Found: " +
                    Bytes.bytesMsg(len);
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

    public static boolean isEdwards(Key key) {
        if (key == null) {
            return false;
        }
        String alg = Assert.hasText(Strings.clean(key.getAlgorithm()), "Key algorithm cannot be null or empty.");
        return "EdDSA".equals(alg) || "XDH".equals(alg) || findById(alg) != null;
    }

    public static EdwardsCurve findById(String id) {
        return REGISTRY.apply(id);
    }

    public static EdwardsCurve forKey(Key key) {
        Assert.notNull(key, "Key cannot be null.");
        String alg = key.getAlgorithm();
        // try constant time lookup first:
        Curve curve = Curves.findByJcaName(alg);
        if (curve instanceof EdwardsCurve) {
            return (EdwardsCurve) curve;
        }

        // Try to find the Key DER algorithm OID:
        byte[] encoded = KeysBridge.findEncoded(key);
        if (!Bytes.isEmpty(encoded)) {
            int subgroupId = findOidSubgroupId(encoded);
            EdwardsCurve crv = BY_OID_SUBGROUP.get(subgroupId);
            if (crv != null) {
                return crv;
            }
        }

        String msg = KeysBridge.typeName(key) + " with algorithm '" + alg + "' is not a recognized " +
                "Edwards Curve key.";
        throw new UnsupportedKeyException(msg);
    }

    static <K extends Key> K assertEdwards(K key) {
        Assert.notNull(key, "Key cannot be null.");
        String alg = key.getAlgorithm();
        if ("EdDSA".equals(alg) || "XDH".equals(alg) || Curves.findByJcaName(alg) instanceof EdwardsCurve) {
            return key;
        }
        byte[] encoded = KeysBridge.findEncoded(key);
        if (!Bytes.isEmpty(encoded)) {
            int subgroupId = findOidSubgroupId(encoded);
            if (subgroupId >= 110 && subgroupId <= 113) {
                return key;
            }
        }

        String msg = KeysBridge.typeName(key) + " with algorithm '" + alg + "' is not a recognized " +
                "Edwards Curve key.";
        throw new UnsupportedKeyException(msg);
    }

    private static int findOidSubgroupId(byte[] encoded) {
        int index = Bytes.indexOf(encoded, DER_OID_PREFIX);
        if (index > -1) {
            index = index + DER_OID_PREFIX.length;
            if (index < encoded.length) {
                return encoded[index];
            }
        }
        return -1;
    }
}
