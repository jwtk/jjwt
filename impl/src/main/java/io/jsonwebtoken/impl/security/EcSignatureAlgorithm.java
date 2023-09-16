/*
 * Copyright (C) 2021 jsonwebtoken.io
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

import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.impl.lang.Bytes;
import io.jsonwebtoken.impl.lang.CheckedFunction;
import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.lang.Collections;
import io.jsonwebtoken.lang.Strings;
import io.jsonwebtoken.security.InvalidKeyException;
import io.jsonwebtoken.security.KeyPairBuilder;
import io.jsonwebtoken.security.SecureRequest;
import io.jsonwebtoken.security.SignatureAlgorithm;
import io.jsonwebtoken.security.SignatureException;
import io.jsonwebtoken.security.VerifySecureDigestRequest;

import java.math.BigInteger;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.ECKey;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

// @since JJWT_RELEASE_VERSION
final class EcSignatureAlgorithm extends AbstractSignatureAlgorithm {

    private static final String REQD_ORDER_BIT_LENGTH_MSG = "orderBitLength must equal 256, 384, or 521.";

    private static final String DER_ENCODING_SYS_PROPERTY_NAME = "io.jsonwebtoken.impl.crypto.EllipticCurveSignatureValidator.derEncodingSupported";

    private static final String ES256_OID = "1.2.840.10045.4.3.2";
    private static final String ES384_OID = "1.2.840.10045.4.3.3";
    private static final String ES512_OID = "1.2.840.10045.4.3.4";

    private static final Set<String> KEY_ALG_NAMES = Collections.setOf("EC", "ECDSA", ES256_OID, ES384_OID, ES512_OID);

    private final ECGenParameterSpec KEY_PAIR_GEN_PARAMS;

    private final int orderBitLength;

    private final String OID;

    /**
     * JWA EC (concat formatted) length in bytes for this instance's {@link #orderBitLength}.
     */
    private final int signatureByteLength;
    private final int sigFieldByteLength;

    private static int shaSize(int orderBitLength) {
        return orderBitLength == 521 ? 512 : orderBitLength;
    }

    /**
     * Returns {@code true} for Order bit lengths defined in the JWA specification, {@code false} otherwise.
     * Specifically, returns {@code true} <em>only</em> for values of {@code 256}, {@code 384} and {@code 521}.  See
     * <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-3.4">RFC 7518, Section 3.4</a> for more.
     *
     * @param orderBitLength the EC key Order bit length to check
     * @return {@code true} for Order bit lengths defined in the JWA specification, {@code false} otherwise.
     */
    private static boolean isSupportedOrderBitLength(int orderBitLength) {
        // This implementation supports only those defined in the JWA specification.
        return orderBitLength == 256 || orderBitLength == 384 || orderBitLength == 521;
    }

    static final EcSignatureAlgorithm ES256 = new EcSignatureAlgorithm(256, ES256_OID);
    static final EcSignatureAlgorithm ES384 = new EcSignatureAlgorithm(384, ES384_OID);
    static final EcSignatureAlgorithm ES512 = new EcSignatureAlgorithm(521, ES512_OID);

    private static final Map<String, SignatureAlgorithm> BY_OID = new LinkedHashMap<>(3);
    static {
        for (EcSignatureAlgorithm alg : Collections.of(ES256, ES384, ES512)) {
            BY_OID.put(alg.OID, alg);
        }
    }

    static SignatureAlgorithm findByKey(Key key) {

        String algName = KeysBridge.findAlgorithm(key);
        if (!Strings.hasText(algName)) {
            return null;
        }
        algName = algName.toUpperCase(Locale.ENGLISH);

        SignatureAlgorithm alg = BY_OID.get(algName);
        if (alg != null) {
            return alg;
        }

        if ("EC".equalsIgnoreCase(algName) || "ECDSA".equalsIgnoreCase(algName)) {
            // some PKCS11 keystores and HSMs won't expose the RSAKey interface, so we can't assume it:
            final int bitLength = KeysBridge.findBitLength(key); // returns -1 if we're unable to find out
            if (bitLength == ES512.orderBitLength) {
                return ES512;
            } else if (bitLength == ES384.orderBitLength) {
                return ES384;
            } else if (bitLength == ES256.orderBitLength) {
                return ES256;
            }
        }

        return null;
    }

    private EcSignatureAlgorithm(int orderBitLength, String oid) {
        super("ES" + shaSize(orderBitLength), "SHA" + shaSize(orderBitLength) + "withECDSA");
        Assert.isTrue(isSupportedOrderBitLength(orderBitLength), REQD_ORDER_BIT_LENGTH_MSG);
        this.OID = Assert.hasText(oid, "Invalid OID.");
        String curveName = "secp" + orderBitLength + "r1";
        this.KEY_PAIR_GEN_PARAMS = new ECGenParameterSpec(curveName);
        this.orderBitLength = orderBitLength;
        this.sigFieldByteLength = Bytes.length(this.orderBitLength);
        this.signatureByteLength = this.sigFieldByteLength * 2; // R bytes + S bytes = concat signature bytes
    }

    @Override
    public KeyPairBuilder keyPair() {
        return new DefaultKeyPairBuilder(ECCurve.KEY_PAIR_GENERATOR_JCA_NAME, this.KEY_PAIR_GEN_PARAMS)
                .random(Randoms.secureRandom());
    }

    @Override
    protected void validateKey(Key key, boolean signing) {
        super.validateKey(key, signing);
        if (!KEY_ALG_NAMES.contains(KeysBridge.findAlgorithm(key))) {
            throw new InvalidKeyException("Unrecognized EC key algorithm name.");
        }
        int size = KeysBridge.findBitLength(key);
        if (size < 0) return; // likely PKCS11 or HSM key, can't get the data we need
        int sigFieldByteLength = Bytes.length(size);
        int concatByteLength = sigFieldByteLength * 2;
        if (concatByteLength != this.signatureByteLength) {
            String msg = "The provided Elliptic Curve " + keyType(signing) +
                    " key size (aka order bit length) is " + Bytes.bitsMsg(size) + ", but the '" +
                    getId() + "' algorithm requires EC Keys with " + Bytes.bitsMsg(this.orderBitLength) +
                    " per [RFC 7518, Section 3.4](https://www.rfc-editor.org/rfc/rfc7518.html#section-3.4).";
            throw new InvalidKeyException(msg);
        }
    }

    @Override
    protected byte[] doDigest(final SecureRequest<byte[], PrivateKey> request) {
        return jca(request).withSignature(new CheckedFunction<Signature, byte[]>() {
            @Override
            public byte[] apply(Signature sig) throws Exception {
                sig.initSign(KeysBridge.root(request));
                sig.update(request.getPayload());
                byte[] signature = sig.sign();
                return transcodeDERToConcat(signature, signatureByteLength);
            }
        });
    }

    boolean isValidRAndS(PublicKey key, byte[] concatSignature) {
        if (key instanceof ECKey) { //Some PKCS11 providers and HSMs won't expose the ECKey interface, so we have to check first
            ECKey ecKey = (ECKey) key;
            BigInteger order = ecKey.getParams().getOrder();
            BigInteger r = new BigInteger(1, Arrays.copyOfRange(concatSignature, 0, sigFieldByteLength));
            BigInteger s = new BigInteger(1, Arrays.copyOfRange(concatSignature, sigFieldByteLength, concatSignature.length));
            return r.signum() >= 1 && s.signum() >= 1 && r.compareTo(order) < 0 && s.compareTo(order) < 0;
        }
        return true;
    }

    @Override
    protected boolean doVerify(final VerifySecureDigestRequest<PublicKey> request) {

        final PublicKey key = request.getKey();

        return jca(request).withSignature(new CheckedFunction<Signature, Boolean>() {
            @Override
            public Boolean apply(Signature sig) {
                byte[] concatSignature = request.getDigest();
                byte[] derSignature;
                try {
                    // mandated per https://www.rfc-editor.org/rfc/rfc7518.html#section-3.4 :
                    if (signatureByteLength != concatSignature.length) {
                        /*
                         * If the expected size is not valid for JOSE, fall back to ASN.1 DER signature IFF the application
                         * is configured to do so.  This fallback is for backwards compatibility ONLY (to support tokens
                         * generated by early versions of jjwt) and backwards compatibility will be removed in a future
                         * version of this library.  This fallback is only enabled if the system property is set to 'true' due to
                         * the risk of CVE-2022-21449 attacks on early JVM versions 15, 17 and 18.
                         */
                        // TODO: remove for 1.0 (DER-encoding support is not in the JWT RFCs)
                        if (concatSignature[0] == 0x30 &&
                                "true".equalsIgnoreCase(System.getProperty(DER_ENCODING_SYS_PROPERTY_NAME))) {
                            derSignature = concatSignature;
                        } else {
                            String msg = "Provided signature is " + Bytes.bytesMsg(concatSignature.length) + " but " +
                                    getId() + " signatures must be exactly " + Bytes.bytesMsg(signatureByteLength) +
                                    " per [RFC 7518, Section 3.4 (validation)]" +
                                    "(https://www.rfc-editor.org/rfc/rfc7518.html#section-3.4).";
                            throw new SignatureException(msg);
                        }
                    } else {
                        //guard for JVM security bug CVE-2022-21449:
                        if (!isValidRAndS(key, concatSignature)) {
                            return false;
                        }

                        // Convert from concat to DER encoding since
                        // 1) SHAXXXWithECDSAInP1363Format algorithms are only available on >= JDK 9 and
                        // 2) the SignatureAlgorithm enum JCA alg names are all SHAXXXwithECDSA (which expects DER formatting)
                        derSignature = transcodeConcatToDER(concatSignature);
                    }

                    sig.initVerify(key);
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

        if ((derSignature[offset - 1] & 0xff) != derSignature.length - offset ||
                (derSignature[offset - 1] & 0xff) != 2 + rLength + 2 + sLength ||
                derSignature[offset] != 2 || derSignature[offset + 2 + rLength] != 2) {
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
