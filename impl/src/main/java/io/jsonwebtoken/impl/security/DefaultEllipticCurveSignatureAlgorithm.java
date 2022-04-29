package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.impl.lang.Bytes;
import io.jsonwebtoken.impl.lang.CheckedFunction;
import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.security.EllipticCurveSignatureAlgorithm;
import io.jsonwebtoken.security.InvalidKeyException;
import io.jsonwebtoken.security.SignatureException;
import io.jsonwebtoken.security.SignatureRequest;
import io.jsonwebtoken.security.VerifySignatureRequest;

import java.math.BigInteger;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.ECKey;
import java.security.spec.ECGenParameterSpec;
import java.text.MessageFormat;
import java.util.Arrays;

public class DefaultEllipticCurveSignatureAlgorithm<SK extends ECKey & PrivateKey, VK extends ECKey & PublicKey> extends AbstractSignatureAlgorithm<SK, VK> implements EllipticCurveSignatureAlgorithm<SK, VK> {

    private static final String REQD_ORDER_BIT_LENGTH_MSG = "orderBitLength must equal 256, 384, or 512.";
    private static final String KEY_TYPE_MSG_PATTERN =
            "Elliptic Curve {0} keys must be {1}s (implement {2}). Provided key type: {3}.";

    private static final String DER_ENCODING_SYS_PROPERTY_NAME =
            "io.jsonwebtoken.impl.crypto.EllipticCurveSignatureValidator.derEncodingSupported";

    private final String curveName;

    private final int orderBitLength;

    /**
     * JWA EC (concat formatted) length in bytes for this instance's {@link #orderBitLength}.
     */
    private final int signatureByteLength;
    private final int sigFieldByteLength;

    private static int shaSize(int orderBitLength) {
        return orderBitLength == 521 ? 512 : orderBitLength;
    }

    /**
     * Returns the correct byte length of an R or S field in a concat signature for the given EC Key order bit length.
     *
     * <p>Per <a href="https://datatracker.ietf.org/doc/html/rfc7518#section-3.4">RFC 7518, Section 3.4</a>:
     * <quote>
     * the Integer-to-OctetString Conversion
     * defined in Section 2.3.7 of SEC1 [SEC1] used to represent R and S as
     * octet sequences adds zero-valued high-order padding bits when needed
     * to round the size up to a multiple of 8 bits; thus, each 521-bit
     * integer is represented using 528 bits in 66 octets.
     * </quote>
     * </p>
     *
     * @param orderBitLength the EC Key order bit length (ecKey.getParams().getOrder().bitLength())
     * @return the correct byte length of an R or S field in a concat signature for the given EC Key order bit length.
     */
    private static int fieldByteLength(int orderBitLength) {
        return (orderBitLength + 7) / Byte.SIZE;
    }

    /**
     * Returns {@code true} for Order bit lengths defined in the JWA specification, {@code false} otherwise.
     * Specifically, returns {@code true} <em>only</em> for values of {@code 256}, {@code 384} and {@code 521}.  See
     * <a href="https://datatracker.ietf.org/doc/html/rfc7518#section-3.4">RFC 7518, Section 3.4</a> for more.
     *
     * @param orderBitLength the EC key Order bit length to check
     * @return {@code true} for Order bit lengths defined in the JWA specification, {@code false} otherwise.
     */
    private static boolean isSupportedOrderBitLength(int orderBitLength) {
        // This implementation supports only those defined in the JWA specification.
        return orderBitLength == 256 || orderBitLength == 384 || orderBitLength == 521;
    }

    public DefaultEllipticCurveSignatureAlgorithm(int orderBitLength) {
        super("ES" + shaSize(orderBitLength), "SHA" + shaSize(orderBitLength) + "withECDSA");
        Assert.isTrue(isSupportedOrderBitLength(orderBitLength), REQD_ORDER_BIT_LENGTH_MSG);
        this.curveName = "secp" + orderBitLength + "r1";
        this.orderBitLength = orderBitLength;
        this.sigFieldByteLength = fieldByteLength(this.orderBitLength);
        this.signatureByteLength = this.sigFieldByteLength * 2; // R bytes + S bytes = concat signature bytes
    }

    @Override
    public KeyPair generateKeyPair() {
        final ECGenParameterSpec spec = new ECGenParameterSpec(this.curveName);
        JcaTemplate template = new JcaTemplate("EC", null);
        return template.execute(KeyPairGenerator.class, new CheckedFunction<KeyPairGenerator, KeyPair>() {
            @Override
            public KeyPair apply(KeyPairGenerator generator) throws Exception {
                generator.initialize(spec, Randoms.secureRandom());
                return generator.generateKeyPair();
            }
        });
    }

    private static void assertKey(Key key, Class<?> type, boolean signing) {
        if (!type.isInstance(key)) {
            String msg = MessageFormat.format(KEY_TYPE_MSG_PATTERN,
                    keyType(signing), type.getSimpleName(), type.getName(), key.getClass().getName());
            throw new InvalidKeyException(msg);
        }
    }

    @Override
    protected void validateKey(Key key, boolean signing) {

        assertKey(key, ECKey.class, signing);
        // https://github.com/jwtk/jjwt/issues/68:
        // Instead of checking for an instance of ECPrivateKey, check for PrivateKey (and ECKey assertion is above):
        Class<?> requiredType = signing ? PrivateKey.class : PublicKey.class;
        assertKey(key, requiredType, signing);

        final String name = getId();
        ECKey ecKey = (ECKey) key;
        BigInteger order = ecKey.getParams().getOrder();
        int orderBitLength = order.bitLength();
        int sigFieldByteLength = fieldByteLength(orderBitLength);
        int concatByteLength = sigFieldByteLength * 2;

        if (concatByteLength != this.signatureByteLength) {
            String msg = "The provided Elliptic Curve " + keyType(signing) + " key's size (aka Order bit length) is " +
                    Bytes.bitsMsg(orderBitLength) + ", but the '" + name + "' algorithm requires EC Keys with " +
                    Bytes.bitsMsg(this.orderBitLength) + " per " +
                    "[RFC 7518, Section 3.4](https://datatracker.ietf.org/doc/html/rfc7518#section-3.4).";
            throw new InvalidKeyException(msg);
        }
    }

    @Override
    protected byte[] doSign(final SignatureRequest<SK> request) {
        return execute(request, Signature.class, new CheckedFunction<Signature, byte[]>() {
            @Override
            public byte[] apply(Signature sig) throws Exception {
                sig.initSign(request.getKey());
                sig.update(request.getPayload());
                byte[] signature = sig.sign();
                return transcodeDERToConcat(signature, signatureByteLength);
            }
        });
    }

    @Override
    protected boolean doVerify(final VerifySignatureRequest<VK> request) {

        final ECKey key = request.getKey();

        return execute(request, Signature.class, new CheckedFunction<Signature, Boolean>() {
            @Override
            public Boolean apply(Signature sig) {
                byte[] concatSignature = request.getDigest();
                byte[] derSignature;
                try {
                    // mandated per https://datatracker.ietf.org/doc/html/rfc7518#section-3.4 :
                    if (signatureByteLength != concatSignature.length) {
                        /*
                         * If the expected size is not valid for JOSE, fall back to ASN.1 DER signature IFF the application
                         * is configured to do so.  This fallback is for backwards compatibility ONLY (to support tokens
                         * generated by early versions of jjwt) and backwards compatibility will be removed in a future
                         * version of this library.  This fallback is only enabled if the system property is set to 'true' due to
                         * the risk of CVE-2022-21449 attacks on early JVM versions 15, 17 and 18.
                         */
                        // TODO: remove for 1.0 (DER-encoding support is not in the JWT RFCs)
                        if (concatSignature[0] == 0x30 && "true".equalsIgnoreCase(System.getProperty(DER_ENCODING_SYS_PROPERTY_NAME))) {
                            derSignature = concatSignature;
                        } else {
                            String msg = "Provided signature is " + Bytes.bytesMsg(concatSignature.length) + " but " +
                                    getId() + " signatures must be exactly " + Bytes.bytesMsg(signatureByteLength) + " per " +
                                    "[RFC 7518, Section 3.4 (validation)](https://datatracker.ietf.org/doc/html/rfc7518#section-3.4).";
                            throw new SignatureException(msg);
                        }
                    } else {
                        //guard for JVM security bug CVE-2022-21449:
                        BigInteger order = key.getParams().getOrder();
                        BigInteger r = new BigInteger(1, Arrays.copyOfRange(concatSignature, 0, sigFieldByteLength));
                        BigInteger s = new BigInteger(1, Arrays.copyOfRange(concatSignature, sigFieldByteLength, concatSignature.length));
                        if (r.signum() < 1 || s.signum() < 1 || r.compareTo(order) >= 0 || s.compareTo(order) >= 0) {
                            return false;
                        }

                        // Convert from concat to DER encoding since
                        // 1) SHAXXXWithECDSAInP1363Format algorithms are only available on >= JDK 9 and
                        // 2) the SignatureAlgorithm enum JCA alg names are all SHAXXXwithECDSA (which expects DER formatting)
                        derSignature = transcodeConcatToDER(concatSignature);
                    }

                    sig.initVerify(request.getKey());
                    sig.update(request.getPayload());
                    return sig.verify(derSignature);

                } catch (Exception e) {
                    String msg = "Unable to verify Elliptic Curve signature using provided ECPublicKey: " + e.getMessage();
                    throw new SignatureException(msg, e);
                }
            }
        });
    }

    /**
     * Transcodes the JCA ASN.1/DER-encoded signature into the concatenated
     * R + S format expected by ECDSA JWS.
     *
     * @param derSignature The ASN1./DER-encoded. Must not be {@code null}.
     * @param outputLength The expected length of the ECDSA JWS signature.
     * @return The ECDSA JWS encoded signature.
     * @throws JwtException If the ASN.1/DER signature format is invalid.
     * @author Martin Treurnicht via <a href="https://github.com/jwtk/jjwt/commit/61510dfca58dd40b4b32c708935126785dcff48c">61510dfca58dd40b4b32c708935126785dcff48c</a>
     */
    public static byte[] transcodeDERToConcat(final byte[] derSignature, int outputLength) throws JwtException {

        if (derSignature.length < 8 || derSignature[0] != 48) {
            throw new JwtException("Invalid ECDSA signature format");
        }

        int offset;
        if (derSignature[1] > 0) {
            offset = 2;
        } else if (derSignature[1] == (byte) 0x81) {
            offset = 3;
        } else {
            throw new JwtException("Invalid ECDSA signature format");
        }

        byte rLength = derSignature[offset + 1];

        int i = rLength;
        while ((i > 0) && (derSignature[(offset + 2 + rLength) - i] == 0)) {
            i--;
        }

        byte sLength = derSignature[offset + 2 + rLength + 1];

        int j = sLength;
        while ((j > 0) && (derSignature[(offset + 2 + rLength + 2 + sLength) - j] == 0)) {
            j--;
        }

        int rawLen = Math.max(i, j);
        rawLen = Math.max(rawLen, outputLength / 2);

        if ((derSignature[offset - 1] & 0xff) != derSignature.length - offset
                || (derSignature[offset - 1] & 0xff) != 2 + rLength + 2 + sLength
                || derSignature[offset] != 2
                || derSignature[offset + 2 + rLength] != 2) {
            throw new JwtException("Invalid ECDSA signature format");
        }

        final byte[] concatSignature = new byte[2 * rawLen];

        System.arraycopy(derSignature, (offset + 2 + rLength) - i, concatSignature, rawLen - i, i);
        System.arraycopy(derSignature, (offset + 2 + rLength + 2 + sLength) - j, concatSignature, 2 * rawLen - j, j);

        return concatSignature;
    }

    /**
     * Transcodes the ECDSA JWS signature into ASN.1/DER format for use by the JCA verifier.
     *
     * @param jwsSignature The JWS signature, consisting of the concatenated R and S values. Must not be {@code null}.
     * @return The ASN.1/DER encoded signature.
     * @throws JwtException If the ECDSA JWS signature format is invalid.
     */
    public static byte[] transcodeConcatToDER(byte[] jwsSignature) throws JwtException {
        try {
            return concatToDER(jwsSignature);
        } catch (Exception e) { // CVE-2022-21449 guard
            String msg = "Invalid ECDSA signature format.";
            throw new SignatureException(msg, e);
        }
    }

    /**
     * Converts the specified concat-encoded signature to a DER-encoded signature.
     *
     * @param jwsSignature concat-encoded signature
     * @return correpsonding DER-encoded signature
     * @throws ArrayIndexOutOfBoundsException if the signature cannot be converted
     * @author Martin Treurnicht via <a href="https://github.com/jwtk/jjwt/commit/61510dfca58dd40b4b32c708935126785dcff48c">61510dfca58dd40b4b32c708935126785dcff48c</a>
     */
    private static byte[] concatToDER(byte[] jwsSignature) throws ArrayIndexOutOfBoundsException {

        int rawLen = jwsSignature.length / 2;

        int i = rawLen;

        while ((i > 0) && (jwsSignature[rawLen - i] == 0)) {
            i--;
        }

        int j = i;

        if (jwsSignature[rawLen - i] < 0) {
            j += 1;
        }

        int k = rawLen;

        while ((k > 0) && (jwsSignature[2 * rawLen - k] == 0)) {
            k--;
        }

        int l = k;

        if (jwsSignature[2 * rawLen - k] < 0) {
            l += 1;
        }

        int len = 2 + j + 2 + l;

        if (len > 255) {
            throw new JwtException("Invalid ECDSA signature format");
        }

        int offset;

        final byte[] derSignature;

        if (len < 128) {
            derSignature = new byte[2 + 2 + j + 2 + l];
            offset = 1;
        } else {
            derSignature = new byte[3 + 2 + j + 2 + l];
            derSignature[1] = (byte) 0x81;
            offset = 2;
        }

        derSignature[0] = 48;
        derSignature[offset++] = (byte) len;
        derSignature[offset++] = 2;
        derSignature[offset++] = (byte) j;

        System.arraycopy(jwsSignature, rawLen - i, derSignature, (offset + j) - i, i);

        offset += j;

        derSignature[offset++] = 2;
        derSignature[offset++] = (byte) l;

        System.arraycopy(jwsSignature, 2 * rawLen - k, derSignature, (offset + l) - k, k);

        return derSignature;
    }
}
