package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.security.AsymmetricKeySignatureAlgorithm;
import io.jsonwebtoken.security.CryptoRequest;
import io.jsonwebtoken.security.InvalidKeyException;
import io.jsonwebtoken.security.VerifySignatureRequest;
import io.jsonwebtoken.security.WeakKeyException;

import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.ECKey;
import java.security.spec.ECGenParameterSpec;

@SuppressWarnings("unused") //used via reflection in the io.jsonwebtoken.security.SignatureAlgorithms class
public class EllipticCurveSignatureAlgorithm extends AbstractSignatureAlgorithm implements AsymmetricKeySignatureAlgorithm {

    private static final String EC_PUBLIC_KEY_REQD_MSG =
        "Elliptic Curve signature validation requires an ECPublicKey instance.";

    private static final int MIN_KEY_LENGTH_BITS = 256;

    private final String curveName;

    private final int minKeyLength; //in bits

    private final int signatureLength;

    public EllipticCurveSignatureAlgorithm(String name, String jcaName, String curveName, int minKeyLength, int signatureLength) {
        super(name, jcaName);
        Assert.hasText(curveName, "Curve name cannot be null or empty.");
        this.curveName = curveName;
        if (minKeyLength < MIN_KEY_LENGTH_BITS) {
            String msg = "minKeyLength bits must be greater than the JWA mandatory minimum key length of " + MIN_KEY_LENGTH_BITS;
            throw new IllegalArgumentException(msg);
        }
        this.minKeyLength = minKeyLength;
        Assert.isTrue(signatureLength > 0, "signatureLength must be greater than zero.");
        this.signatureLength = signatureLength;
    }

    @Override
    public KeyPair generateKeyPair() {
        KeyPairGenerator keyGenerator;
        try {
            keyGenerator = KeyPairGenerator.getInstance("EC");
            ECGenParameterSpec spec = new ECGenParameterSpec(this.curveName);
            keyGenerator.initialize(spec, Randoms.secureRandom());
        } catch (Exception e) {
            throw new IllegalStateException("Unable to obtain an EllipticCurve KeyPairGenerator: " + e.getMessage(), e);
        }
        return keyGenerator.genKeyPair();
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

        final String name = getName();
        ECKey ecKey = (ECKey) key;
        int size = ecKey.getParams().getOrder().bitLength();
        if (size < this.minKeyLength) {
            String msg = "The " + keyType(signing) + " key's size (ECParameterSpec order) is " + size +
                " bits which is not secure enough for the " + name + " algorithm.  The JWT " +
                "JWA Specification (RFC 7518, Section 3.4) states that keys used with " +
                name + " MUST have a size >= " + this.minKeyLength +
                " bits.  Consider using the SignatureAlgorithms." + name + ".generateKeyPair() " +
                "method to create a key pair guaranteed to be secure enough for " + name + ".  See " +
                "https://tools.ietf.org/html/rfc7518#section-3.4 for more information.";
            throw new WeakKeyException(msg);
        }
    }

    @Override
    protected byte[] doSign(CryptoRequest<byte[], Key> request) throws Exception {
        PrivateKey privateKey = (PrivateKey) request.getKey();
        Signature sig = createSignatureInstance(request.getProvider(), null);
        sig.initSign(privateKey);
        sig.update(request.getData());
        return transcodeSignatureToConcat(sig.sign(), signatureLength);
    }

    @Override
    protected boolean doVerify(VerifySignatureRequest request) throws Exception {
        final Key key = request.getKey();
        PublicKey publicKey = (PublicKey) key;
        Signature sig = createSignatureInstance(request.getProvider(), null);
        byte[] signature = request.getSignature();
        /*
         * If the expected size is not valid for JOSE, fall back to ASN.1 DER signature.
         * This fallback is for backwards compatibility ONLY (to support tokens generated by previous versions of jjwt)
         * and backwards compatibility will possibly be removed in a future version of this library.
         */
        byte[] derSignature = this.signatureLength != signature.length && signature[0] == 0x30 ? signature : transcodeSignatureToDER(signature);
        sig.initVerify(publicKey);
        sig.update(request.getData());
        return sig.verify(derSignature);
    }

    /**
     * Transcodes the JCA ASN.1/DER-encoded signature into the concatenated
     * R + S format expected by ECDSA JWS.
     *
     * @param derSignature The ASN1./DER-encoded. Must not be {@code null}.
     * @param outputLength The expected length of the ECDSA JWS signature.
     * @return The ECDSA JWS encoded signature.
     * @throws JwtException If the ASN.1/DER signature format is invalid.
     */
    public static byte[] transcodeSignatureToConcat(final byte[] derSignature, int outputLength) throws JwtException {

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
     * Transcodes the ECDSA JWS signature into ASN.1/DER format for use by
     * the JCA verifier.
     *
     * @param jwsSignature The JWS signature, consisting of the
     *                     concatenated R and S values. Must not be
     *                     {@code null}.
     * @return The ASN.1/DER encoded signature.
     * @throws JwtException If the ECDSA JWS signature format is invalid.
     */
    public static byte[] transcodeSignatureToDER(byte[] jwsSignature) throws JwtException {

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
