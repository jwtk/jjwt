/*
 * Copyright (C) 2019 jsonwebtoken.io
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

import io.jsonwebtoken.impl.lang.CheckedFunction;
import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.lang.Collections;
import io.jsonwebtoken.lang.Strings;
import io.jsonwebtoken.security.InvalidKeyException;
import io.jsonwebtoken.security.KeyPairBuilder;
import io.jsonwebtoken.security.SecureRequest;
import io.jsonwebtoken.security.SignatureAlgorithm;
import io.jsonwebtoken.security.VerifySecureDigestRequest;
import io.jsonwebtoken.security.WeakKeyException;

import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * @since JJWT_RELEASE_VERSION
 */
final class RsaSignatureAlgorithm extends AbstractSignatureAlgorithm {

    // Defined in https://www.rfc-editor.org/rfc/rfc8017#appendix-A.1:
    //private static final String RSA_ENC_OID = "1.2.840.113549.1.1.1"; // RFC 8017's "rsaEncryption"

    // Defined in https://www.rfc-editor.org/rfc/rfc8017#appendix-A.2.3:
    static final String PSS_JCA_NAME = "RSASSA-PSS";
    static final String PSS_OID = "1.2.840.113549.1.1.10"; // RFC 8017's "id-RSASSA-PSS"

    // Defined in https://www.rfc-editor.org/rfc/rfc8017#appendix-A.2.4:
    private static final String RS256_OID = "1.2.840.113549.1.1.11"; // RFC 8017's "sha256WithRSAEncryption"
    private static final String RS384_OID = "1.2.840.113549.1.1.12"; // RFC 8017's "sha384WithRSAEncryption"
    private static final String RS512_OID = "1.2.840.113549.1.1.13"; // RFC 8017's "sha512WithRSAEncryption"

    private static final Set<String> PSS_ALG_NAMES = Collections.setOf(PSS_JCA_NAME, PSS_OID);

    private static final Set<String> KEY_ALG_NAMES =
            Collections.setOf("RSA", PSS_JCA_NAME, PSS_OID, RS256_OID, RS384_OID, RS512_OID);

    private static final int MIN_KEY_BIT_LENGTH = 2048;

    private static AlgorithmParameterSpec pssParamSpec(int digestBitLength) {
        MGF1ParameterSpec ps = new MGF1ParameterSpec("SHA-" + digestBitLength);
        int saltByteLength = digestBitLength / Byte.SIZE;
        return new PSSParameterSpec(ps.getDigestAlgorithm(), "MGF1", ps, saltByteLength, 1);
    }

    private static SignatureAlgorithm rsaSsaPss(int digestBitLength) {
        return new RsaSignatureAlgorithm(digestBitLength, pssParamSpec(digestBitLength));
    }

    static final SignatureAlgorithm RS256 = new RsaSignatureAlgorithm(256);
    static final SignatureAlgorithm RS384 = new RsaSignatureAlgorithm(384);
    static final SignatureAlgorithm RS512 = new RsaSignatureAlgorithm(512);
    static final SignatureAlgorithm PS256 = rsaSsaPss(256);
    static final SignatureAlgorithm PS384 = rsaSsaPss(384);
    static final SignatureAlgorithm PS512 = rsaSsaPss(512);

    private static final Map<String, SignatureAlgorithm> PKCSv15_ALGS;

    static {
        PKCSv15_ALGS = new LinkedHashMap<>();
        PKCSv15_ALGS.put(RS256_OID, RS256);
        PKCSv15_ALGS.put(RS384_OID, RS384);
        PKCSv15_ALGS.put(RS512_OID, RS512);
    }

    private final int preferredKeyBitLength;

    private final AlgorithmParameterSpec algorithmParameterSpec;

    private RsaSignatureAlgorithm(String name, String jcaName, int digestBitLength, AlgorithmParameterSpec paramSpec) {
        super(name, jcaName);
        this.preferredKeyBitLength = digestBitLength * Byte.SIZE; // RSA invariant
        // invariant since this is a protected constructor:
        Assert.state(this.preferredKeyBitLength >= MIN_KEY_BIT_LENGTH);
        this.algorithmParameterSpec = paramSpec;
    }

    private RsaSignatureAlgorithm(int digestBitLength) {
        this("RS" + digestBitLength, "SHA" + digestBitLength + "withRSA", digestBitLength, null);
    }

    // RSASSA-PSS constructor
    private RsaSignatureAlgorithm(int digestBitLength, AlgorithmParameterSpec paramSpec) {
        this("PS" + digestBitLength, PSS_JCA_NAME, digestBitLength, paramSpec);
    }

    static SignatureAlgorithm findByKey(Key key) {

        String algName = KeysBridge.findAlgorithm(key);
        if (!Strings.hasText(algName)) {
            return null;
        }
        algName = algName.toUpperCase(Locale.ENGLISH); // for checking against name Sets

        // some PKCS11 keystores and HSMs won't expose the RSAKey interface, so we can't assume it:
        final int bitLength = KeysBridge.findBitLength(key); // returns -1 if we're unable to find out

        if (PSS_ALG_NAMES.contains(algName)) { // generic RSASSA-PSS names, check for key lengths:
            // even though we found an RSASSA-PSS key, we need to confirm that the key length is
            // sufficient if the encoded key bytes are available:
            if (bitLength >= 4096) {
                return PS512;
            } else if (bitLength >= 3072) {
                return PS384;
            } else if (bitLength >= MIN_KEY_BIT_LENGTH) {
                return PS256;
            }
        }

        // unable to resolve/recommend an RSASSA-PSS alg, so try PKCS v 1.5 algs by OID:
        SignatureAlgorithm alg = PKCSv15_ALGS.get(algName);
        if (alg != null) {
            return alg;
        }

        if ("RSA".equals(algName)) {
            if (bitLength >= 4096) {
                return RS512;
            } else if (bitLength >= 3072) {
                return RS384;
            } else if (bitLength >= MIN_KEY_BIT_LENGTH) {
                return RS256;
            }
        }

        return null;
    }

    static boolean isPss(Key key) {
        String alg = KeysBridge.findAlgorithm(key);
        return PSS_ALG_NAMES.contains(alg);
    }

    @SuppressWarnings("BooleanMethodIsAlwaysInverted")
    static boolean isRsaAlgorithmName(Key key) {
        String alg = KeysBridge.findAlgorithm(key);
        return KEY_ALG_NAMES.contains(alg);
    }

    @Override
    public KeyPairBuilder keyPair() {
        final String jcaName = this.algorithmParameterSpec != null ? PSS_JCA_NAME : "RSA";

        //TODO: JDK 8 or later, for RSASSA-PSS, use the following instead of what is below:
        //
        // AlgorithmParameterSpec keyGenSpec = new RSAKeyGenParameterSpec(this.preferredKeyBitLength,
        //     RSAKeyGenParameterSpec.F4, this.algorithmParameterSpec);
        // return new DefaultKeyPairBuilder(jcaName, keyGenSpec).provider(getProvider()).random(Randoms.secureRandom());
        //

        return new DefaultKeyPairBuilder(jcaName, this.preferredKeyBitLength).random(Randoms.secureRandom());
    }

    @Override
    protected void validateKey(Key key, boolean signing) {
        super.validateKey(key, signing);
        if (!isRsaAlgorithmName(key)) {
            throw new InvalidKeyException("Unrecognized RSA or RSASSA-PSS key algorithm name.");
        }
        int size = KeysBridge.findBitLength(key);
        if (size < 0) return; // https://github.com/jwtk/jjwt/issues/68
        if (size < MIN_KEY_BIT_LENGTH) {
            String id = getId();
            String section = id.startsWith("PS") ? "3.5" : "3.3";
            String msg = "The RSA " + keyType(signing) + " key size (aka modulus bit length) is " + size + " bits " +
                    "which is not secure enough for the " + id + " algorithm.  The JWT JWA Specification " +
                    "(RFC 7518, Section " + section + ") states that RSA keys MUST have a size >= " +
                    MIN_KEY_BIT_LENGTH + " bits.  Consider using the Jwts.SIG." + id +
                    ".keyPair() builder to create a KeyPair guaranteed to be secure enough for " + id + ".  See " +
                    "https://tools.ietf.org/html/rfc7518#section-" + section + " for more information.";
            throw new WeakKeyException(msg);
        }
    }

    @Override
    protected byte[] doDigest(final SecureRequest<byte[], PrivateKey> request) {
        return jca(request).withSignature(new CheckedFunction<Signature, byte[]>() {
            @Override
            public byte[] apply(Signature sig) throws Exception {
                if (algorithmParameterSpec != null) {
                    sig.setParameter(algorithmParameterSpec);
                }
                sig.initSign(request.getKey());
                sig.update(request.getPayload());
                return sig.sign();
            }
        });
    }

    @Override
    protected boolean doVerify(final VerifySecureDigestRequest<PublicKey> request) {
        return jca(request).withSignature(new CheckedFunction<Signature, Boolean>() {
            @Override
            public Boolean apply(Signature sig) throws Exception {
                if (algorithmParameterSpec != null) {
                    sig.setParameter(algorithmParameterSpec);
                }
                sig.initVerify(request.getKey());
                sig.update(request.getPayload());
                return sig.verify(request.getDigest());
            }
        });
    }
}
