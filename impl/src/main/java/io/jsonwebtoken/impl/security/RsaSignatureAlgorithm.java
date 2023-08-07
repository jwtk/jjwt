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
import io.jsonwebtoken.impl.lang.CheckedSupplier;
import io.jsonwebtoken.impl.lang.Conditions;
import io.jsonwebtoken.security.InvalidKeyException;
import io.jsonwebtoken.security.KeyPairBuilder;
import io.jsonwebtoken.security.SecureRequest;
import io.jsonwebtoken.security.VerifySecureDigestRequest;
import io.jsonwebtoken.security.WeakKeyException;

import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.RSAKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;

/**
 * @since JJWT_RELEASE_VERSION
 */
public class RsaSignatureAlgorithm extends AbstractSignatureAlgorithm {

    private static final String PSS_JCA_NAME = "RSASSA-PSS";
    private static final int MIN_KEY_BIT_LENGTH = 2048;

    private static AlgorithmParameterSpec pssParamFromSaltBitLength(int saltBitLength) {
        MGF1ParameterSpec ps = new MGF1ParameterSpec("SHA-" + saltBitLength);
        int saltByteLength = saltBitLength / Byte.SIZE;
        return new PSSParameterSpec(ps.getDigestAlgorithm(), "MGF1", ps, saltByteLength, 1);
    }

    private final int preferredKeyBitLength;

    private final AlgorithmParameterSpec algorithmParameterSpec;

    public RsaSignatureAlgorithm(String name, String jcaName, int preferredKeyBitLength, AlgorithmParameterSpec algParam) {
        super(name, jcaName);
        if (preferredKeyBitLength < MIN_KEY_BIT_LENGTH) {
            String msg = "preferredKeyBitLength must be greater than the JWA mandatory minimum key length of " +
                    MIN_KEY_BIT_LENGTH;
            throw new IllegalArgumentException(msg);
        }
        this.preferredKeyBitLength = preferredKeyBitLength;
        this.algorithmParameterSpec = algParam;
    }

    public RsaSignatureAlgorithm(int digestBitLength, int preferredKeyBitLength) {
        this("RS" + digestBitLength, "SHA" + digestBitLength + "withRSA", preferredKeyBitLength, null);
    }

    public RsaSignatureAlgorithm(int digestBitLength, int preferredKeyBitLength, int pssSaltBitLength) {
        this("PS" + digestBitLength, PSS_JCA_NAME, preferredKeyBitLength, pssParamFromSaltBitLength(pssSaltBitLength));
        // PSS is not available natively until JDK 11, so try to load BC as a backup provider if possible on <= JDK 10:
        setProvider(Providers.findBouncyCastle(Conditions.notExists(new CheckedSupplier<Signature>() {
            @Override
            public Signature get() throws Exception {
                return Signature.getInstance(PSS_JCA_NAME);
            }
        })));
    }

    @Override
    public KeyPairBuilder keyPair() {
        return new DefaultKeyPairBuilder("RSA", this.preferredKeyBitLength)
                .provider(getProvider())
                .random(Randoms.secureRandom());
    }

    @Override
    protected void validateKey(Key key, boolean signing) {

        // https://github.com/jwtk/jjwt/issues/68
        if (signing && !(key instanceof PrivateKey)) {
            String msg = "Asymmetric key signatures must be created with PrivateKeys. The specified key is of type: " +
                    key.getClass().getName();
            throw new InvalidKeyException(msg);
        }

        // Some PKCS11 providers and HSMs won't expose the RSAKey interface, so we have to check to see if we can cast
        // If so, we can provide additional safety checks:
        if (key instanceof RSAKey) {
            RSAKey rsaKey = (RSAKey) key;
            int size = rsaKey.getModulus().bitLength();
            if (size < MIN_KEY_BIT_LENGTH) {
                String id = getId();
                String section = id.startsWith("PS") ? "3.5" : "3.3";
                String msg = "The " + keyType(signing) + " key's size is " + size + " bits which is not secure " +
                        "enough for the " + id + " algorithm.  The JWT JWA Specification (RFC 7518, Section " +
                        section + ") states that RSA keys MUST have a size >= " + MIN_KEY_BIT_LENGTH + " bits.  " +
                        "Consider using the Jwts.SIG." + id + ".generateKeyPair() " + "method to create a " +
                        "key pair guaranteed to be secure enough for " + id + ".  See " +
                        "https://tools.ietf.org/html/rfc7518#section-" + section + " for more information.";
                throw new WeakKeyException(msg);
            }
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
        final Key key = request.getKey();
        if (key instanceof PrivateKey) { //legacy support only TODO: remove for 1.0
            return super.messageDigest(request);
        }
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
