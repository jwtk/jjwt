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
import io.jsonwebtoken.security.WeakKeyException;

import java.math.BigInteger;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.ECKey;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;

public class DefaultEllipticCurveSignatureAlgorithm<SK extends ECKey & PrivateKey, VK extends ECKey & PublicKey> extends AbstractSignatureAlgorithm<SK, VK> implements EllipticCurveSignatureAlgorithm<SK, VK> {

    private static final String EC_PUBLIC_KEY_REQD_MSG =
            "Elliptic Curve signature validation requires an ECPublicKey instance.";

    private static final String DER_ENCODING_SYS_PROPERTY_NAME =
            "io.jsonwebtoken.impl.crypto.EllipticCurveSignatureValidator.derEncodingSupported";

    private static final int MIN_KEY_LENGTH_BITS = 256;

    private final String curveName;

    private final int minKeyBitLength; //in bits

    private final int signatureByteLength;
    private final int keyFieldByteLength;

    private static int shaSize(int keyBitLength) {
        return keyBitLength == 521 ? 512 : keyBitLength;
    }

    public DefaultEllipticCurveSignatureAlgorithm(int keyBitLength, int signatureByteLength) {
        this("ES" + shaSize(keyBitLength), "SHA" + shaSize(keyBitLength) + "withECDSA", "secp" + keyBitLength + "r1", keyBitLength, signatureByteLength);
    }

    public DefaultEllipticCurveSignatureAlgorithm(String name, String jcaName, String curveName, int minKeyBitLength, int signatureByteLength) {
        super(name, jcaName);
        Assert.hasText(curveName, "Curve name cannot be null or empty.");
        this.curveName = curveName;
        if (minKeyBitLength < MIN_KEY_LENGTH_BITS) {
            String msg = "minKeyLength bits must be greater than the JWA mandatory minimum key length of " + MIN_KEY_LENGTH_BITS;
            throw new IllegalArgumentException(msg);
        }
        this.minKeyBitLength = minKeyBitLength;
        Assert.isTrue(signatureByteLength > 0, "signatureLength must be greater than zero.");
        this.signatureByteLength = signatureByteLength;
        this.keyFieldByteLength = this.signatureByteLength / 2;
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

    @Override
    protected void validateKey(Key key, boolean signing) {

        if (!(key instanceof ECKey)) {
            String msg = "EC " + keyType(signing) + " keys must be an ECKey.  The specified key is of type: " +
                    key.getClass().getName();
            throw new InvalidKeyException(msg);
        }

        if (signing) {
            // https://github.com/jwtk/jjwt/issues/68
            // Instead of checking for an instance of ECPrivateKey, check for PrivateKey (and ECKey assertion is above):
            if (!(key instanceof PrivateKey)) {
                String msg = "Asymmetric key signatures must be created with PrivateKeys. The specified key is of type: " +
                        key.getClass().getName();
                throw new InvalidKeyException(msg);
            }
        } else { //verification
            if (!(key instanceof PublicKey)) {
                throw new InvalidKeyException(EC_PUBLIC_KEY_REQD_MSG);
            }
        }

        final String name = getId();
        ECKey ecKey = (ECKey) key;
        BigInteger order = ecKey.getParams().getOrder();
        int orderBitLength = order.bitLength();
        if (orderBitLength < this.minKeyBitLength) {
            String msg = "The " + keyType(signing) + " key's size (ECParameterSpec order) is " + orderBitLength +
                    " bits which is not secure enough for the " + name + " algorithm.  The JWT " +
                    "JWA Specification (RFC 7518, Section 3.4) states that keys used with " +
                    name + " MUST have a size >= " + this.minKeyBitLength +
                    " bits.  Consider using the SignatureAlgorithms." + name + ".generateKeyPair() " +
                    "method to create a key pair guaranteed to be secure enough for " + name + ".  See " +
                    "https://tools.ietf.org/html/rfc7518#section-3.4 for more information.";
            throw new WeakKeyException(msg);
        }

        int keyFieldByteLength = (orderBitLength + 7) / Byte.SIZE; //for ES512 (can be 65 or 66, this ensures 66)
        int concatByteLength = keyFieldByteLength * 2;

        if (concatByteLength != this.signatureByteLength) {
            String msg = "EllipticCurve key has a field size of " + Bytes.bytesMsg(keyFieldByteLength) + ", but " +
                    getId() + " requires a field size of " + Bytes.bytesMsg(this.keyFieldByteLength) +
                    " per [RFC 7518, Section 3.4 (validation)]" +
                    "(https://datatracker.ietf.org/doc/html/rfc7518#section-3.4).";
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
                        BigInteger r = new BigInteger(1, Arrays.copyOfRange(concatSignature, 0, keyFieldByteLength));
                        BigInteger s = new BigInteger(1, Arrays.copyOfRange(concatSignature, keyFieldByteLength, concatSignature.length));
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
