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

import io.jsonwebtoken.JweHeader;
import io.jsonwebtoken.impl.DefaultJweHeader;
import io.jsonwebtoken.impl.lang.Bytes;
import io.jsonwebtoken.impl.lang.CheckedFunction;
import io.jsonwebtoken.impl.lang.FieldReadable;
import io.jsonwebtoken.impl.lang.RequiredFieldReader;
import io.jsonwebtoken.lang.Arrays;
import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.security.AeadAlgorithm;
import io.jsonwebtoken.security.DecryptionKeyRequest;
import io.jsonwebtoken.security.EcPublicJwk;
import io.jsonwebtoken.security.InvalidKeyException;
import io.jsonwebtoken.security.Jwks;
import io.jsonwebtoken.security.KeyAlgorithm;
import io.jsonwebtoken.security.KeyLengthSupplier;
import io.jsonwebtoken.security.KeyRequest;
import io.jsonwebtoken.security.KeyResult;
import io.jsonwebtoken.security.OctetPublicJwk;
import io.jsonwebtoken.security.ProtoJwkBuilder;
import io.jsonwebtoken.security.PublicJwk;
import io.jsonwebtoken.security.Request;
import io.jsonwebtoken.security.SecureRequest;
import io.jsonwebtoken.security.SecurityException;
import io.jsonwebtoken.security.UnsupportedKeyException;

import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.ECKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;

/**
 * @since JJWT_RELEASE_VERSION
 */
class EcdhKeyAlgorithm extends CryptoAlgorithm implements KeyAlgorithm<PublicKey, PrivateKey> {

    protected static final String JCA_NAME = "ECDH";
    protected static final String XDH_JCA_NAME = "XDH";
    protected static final String DEFAULT_ID = JCA_NAME + "-ES";

    // Per https://www.rfc-editor.org/rfc/rfc7518.html#section-4.6.2, 2nd paragraph:
    //    Key derivation is performed using the Concat KDF, as defined in
    //    Section 5.8.1 of [NIST.800-56A](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-56Ar2.pdf),
    //    where the Digest Method is SHA-256.
    private static final String CONCAT_KDF_HASH_ALG_NAME = "SHA-256";
    private static final ConcatKDF CONCAT_KDF = new ConcatKDF(CONCAT_KDF_HASH_ALG_NAME);
    public static final String KEK_TYPE_MESSAGE = "Key Encryption Key must be a " + ECKey.class.getName() +
            " or valid Edwards Curve PublicKey instance.";
    public static final String KDK_TYPE_MESSAGE = "Key Decryption Key must be a " + ECKey.class.getName() +
            " or valid Edwards Curve PrivateKey instance.";

    private final KeyAlgorithm<SecretKey, SecretKey> WRAP_ALG;

    private static String idFor(KeyAlgorithm<SecretKey, SecretKey> wrapAlg) {
        return wrapAlg instanceof DirectKeyAlgorithm ? DEFAULT_ID : DEFAULT_ID + "+" + wrapAlg.getId();
    }

    EcdhKeyAlgorithm() {
        // default ECDH-ES doesn't do a wrap, so we use DirectKeyAlgorithm which is a no-op.  That is, we're using
        // the Null Object Design Pattern so we don't have to check for null depending on if key wrapping is used or not
        this(new DirectKeyAlgorithm());
    }

    EcdhKeyAlgorithm(KeyAlgorithm<SecretKey, SecretKey> wrapAlg) {
        super(idFor(wrapAlg), JCA_NAME);
        this.WRAP_ALG = Assert.notNull(wrapAlg, "Wrap algorithm cannot be null.");
    }

    //visible for testing, for non-Edwards elliptic curves
    protected KeyPair generateKeyPair(final Request<?> request, final ECParameterSpec spec) {
        Assert.notNull(spec, "request key params cannot be null.");
        JcaTemplate template = new JcaTemplate(ECCurve.KEY_PAIR_GENERATOR_JCA_NAME, getProvider(request), ensureSecureRandom(request));
        return template.generateKeyPair(spec);
    }

    //visible for testing, for Edwards elliptic curves
    protected KeyPair generateKeyPair(SecureRandom random, EdwardsCurve curve, Provider provider) {
        return curve.keyPairBuilder().setProvider(provider).setRandom(random).build();
    }

    protected byte[] generateZ(final KeyRequest<?> request, final PublicKey pub, final PrivateKey priv) {
        return jca(request).withKeyAgreement(new CheckedFunction<KeyAgreement, byte[]>() {
            @Override
            public byte[] apply(KeyAgreement keyAgreement) throws Exception {
                keyAgreement.init(priv, ensureSecureRandom(request));
                keyAgreement.doPhase(pub, true);
                return keyAgreement.generateSecret();
            }
        });
    }

    protected String getConcatKDFAlgorithmId(AeadAlgorithm enc) {
        return this.WRAP_ALG instanceof DirectKeyAlgorithm ?
                Assert.hasText(enc.getId(), "AeadAlgorithm id cannot be null or empty.") :
                getId();
    }

    private byte[] createOtherInfo(int keydatalen, String AlgorithmID, byte[] PartyUInfo, byte[] PartyVInfo) {

        // https://www.rfc-editor.org/rfc/rfc7518.html#section-4.6.2 "AlgorithmID":
        Assert.hasText(AlgorithmID, "AlgorithmId cannot be null or empty.");
        byte[] algIdBytes = AlgorithmID.getBytes(StandardCharsets.US_ASCII);

        PartyUInfo = Arrays.length(PartyUInfo) == 0 ? Bytes.EMPTY : PartyUInfo; // ensure not null
        PartyVInfo = Arrays.length(PartyVInfo) == 0 ? Bytes.EMPTY : PartyVInfo; // ensure not null

        // Values and order defined in https://www.rfc-editor.org/rfc/rfc7518.html#section-4.6.2 and
        // https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-56Ar2.pdf section 5.8.1.2 :
        return Bytes.concat(
                Bytes.toBytes(algIdBytes.length), algIdBytes, // AlgorithmID
                Bytes.toBytes(PartyUInfo.length), PartyUInfo, // PartyUInfo
                Bytes.toBytes(PartyVInfo.length), PartyVInfo, // PartyVInfo
                Bytes.toBytes(keydatalen),                    // SuppPubInfo per https://www.rfc-editor.org/rfc/rfc7518.html#section-4.6.2
                Bytes.EMPTY                                   // SuppPrivInfo empty per https://www.rfc-editor.org/rfc/rfc7518.html#section-4.6.2
        );
    }

    private int getKeyBitLength(AeadAlgorithm enc) {
        int bitLength = this.WRAP_ALG instanceof KeyLengthSupplier ?
                ((KeyLengthSupplier) this.WRAP_ALG).getKeyBitLength() : enc.getKeyBitLength();
        return Assert.gt(bitLength, 0, "Algorithm keyBitLength must be > 0");
    }

    private SecretKey deriveKey(KeyRequest<?> request, PublicKey publicKey, PrivateKey privateKey) {
        AeadAlgorithm enc = Assert.notNull(request.getEncryptionAlgorithm(), "Request encryptionAlgorithm cannot be null.");
        int requiredCekBitLen = getKeyBitLength(enc);
        final String AlgorithmID = getConcatKDFAlgorithmId(enc);
        byte[] apu = request.getHeader().getAgreementPartyUInfo();
        byte[] apv = request.getHeader().getAgreementPartyVInfo();
        byte[] OtherInfo = createOtherInfo(requiredCekBitLen, AlgorithmID, apu, apv);
        byte[] Z = generateZ(request, publicKey, privateKey);
        return CONCAT_KDF.deriveKey(Z, requiredCekBitLen, OtherInfo);
    }

    @Override
    protected String getJcaName(Request<?> request) {
        if (request instanceof SecureRequest) {
            return ((SecureRequest<?, ?>) request).getKey() instanceof ECKey ? super.getJcaName(request) : XDH_JCA_NAME;
        } else {
            return request.getPayload() instanceof ECKey ? super.getJcaName(request) : XDH_JCA_NAME;
        }
    }

    private static EdwardsCurve assertAgreement(Key key, String exMsg) {
        EdwardsCurve curve;
        try {
            curve = EdwardsCurve.forKey(key);
        } catch (Exception e) {
            throw new UnsupportedKeyException(exMsg + " Cause: " + e.getMessage(), e);
        }
        Assert.stateNotNull(curve, "EdwardsCurve instance cannot be null.");
        if (curve.isSignatureCurve()) {
            String msg = curve.getId() + " keys may not be used with ECDH-ES key agreement algorithms per " +
                    "https://www.rfc-editor.org/rfc/rfc8037#section-3.1";
            throw new UnsupportedKeyException(msg);
        }
        return curve;
    }

    @Override
    public KeyResult getEncryptionKey(KeyRequest<PublicKey> request) throws SecurityException {
        Assert.notNull(request, "Request cannot be null.");
        JweHeader header = Assert.notNull(request.getHeader(), "Request JweHeader cannot be null.");
        PublicKey publicKey = Assert.notNull(request.getPayload(), "Encryption PublicKey cannot be null.");

        KeyPair pair; // generated (ephemeral) key pair
        final SecureRandom random = ensureSecureRandom(request);
        ProtoJwkBuilder<?, ?> jwkBuilder = Jwks.builder().setRandom(random);

        if (publicKey instanceof ECKey) {
            ECKey ecPublicKey = (ECKey) publicKey;
            ECParameterSpec spec = Assert.notNull(ecPublicKey.getParams(), "Encryption PublicKey params cannot be null.");
            // note: we don't need to validate if specified key's point is on a supported curve here
            // because that will automatically be asserted when using Jwks.builder().... below
            pair = generateKeyPair(request, spec);
            // assert pair key types:
            KeyPairs.getKey(pair, ECPublicKey.class);
            KeyPairs.getKey(pair, ECPrivateKey.class);
        } else { // it must be an edwards curve key
            EdwardsCurve curve = assertAgreement(publicKey, KEK_TYPE_MESSAGE);
            Provider provider = request.getProvider();
            Provider curveProvider = curve.getProvider(); // only non-null if not natively supported by the JVM
            if (provider == null && curveProvider != null) { // ensure that BC can be used if necessary:
                provider = curveProvider;
                request = new DefaultKeyRequest<>(request.getPayload(), provider, random,
                        request.getHeader(), request.getEncryptionAlgorithm());
            }
            pair = generateKeyPair(random, curve, provider);
            jwkBuilder.setProvider(provider);
        }

        Assert.stateNotNull(pair, "Internal implementation state: KeyPair cannot be null.");

        // This asserts that the generated public key (and therefore the request key) is on a JWK-supported curve:
        PublicJwk<?> jwk = jwkBuilder.forKey(pair.getPublic()).build();

        final SecretKey derived = deriveKey(request, publicKey, pair.getPrivate());

        DefaultKeyRequest<SecretKey> wrapReq =
                new DefaultKeyRequest<>(derived, request.getProvider(), request.getSecureRandom(),
                        request.getHeader(), request.getEncryptionAlgorithm());
        KeyResult result = WRAP_ALG.getEncryptionKey(wrapReq);

        header.put(DefaultJweHeader.EPK.getId(), jwk);

        return result;
    }

    @Override
    public SecretKey getDecryptionKey(DecryptionKeyRequest<PrivateKey> request) throws SecurityException {

        Assert.notNull(request, "Request cannot be null.");
        JweHeader header = Assert.notNull(request.getHeader(), "Request JweHeader cannot be null.");
        PrivateKey privateKey = Assert.notNull(request.getKey(), "Decryption PrivateKey cannot be null.");
        FieldReadable reader = new RequiredFieldReader(header);
        PublicJwk<?> epk = reader.get(DefaultJweHeader.EPK);

        if (privateKey instanceof ECKey) {
            ECKey ecPrivateKey = (ECKey) privateKey;
            if (!(epk instanceof EcPublicJwk)) {
                String msg = "JWE Header " + DefaultJweHeader.EPK + " value is not a supported Elliptic Curve " +
                        "Public JWK. Value: " + epk;
                throw new UnsupportedKeyException(msg);
            }
            EcPublicJwk ecEpk = (EcPublicJwk) epk;
            // While the EPK might be on a JWA-supported NIST curve, it must be on the private key's exact curve:
            if (!EcPublicJwkFactory.contains(ecPrivateKey.getParams().getCurve(), ecEpk.toKey().getW())) {
                String msg = "JWE Header " + DefaultJweHeader.EPK + " value does not represent " +
                        "a point on the expected curve.";
                throw new InvalidKeyException(msg);
            }
        } else { // it must be an Edwards Curve key
            EdwardsCurve privateKeyCurve = assertAgreement(privateKey, KDK_TYPE_MESSAGE);
            if (!(epk instanceof OctetPublicJwk)) {
                String msg = "JWE Header " + DefaultJweHeader.EPK + " value is not a supported Elliptic Curve " +
                        "Public JWK. Value: " + epk;
                throw new UnsupportedKeyException(msg);
            }
            OctetPublicJwk<?> oEpk = (OctetPublicJwk<?>) epk;
            EdwardsCurve epkCurve = EdwardsCurve.forKey(oEpk.toKey());
            if (!privateKeyCurve.equals(epkCurve)) {
                String msg = "JWE Header " + DefaultJweHeader.EPK + " value does not represent a point " +
                        "on the expected curve. Value: " + oEpk;
                throw new InvalidKeyException(msg);
            }
            Provider curveProvider = privateKeyCurve.getProvider();
            if (request.getProvider() == null && curveProvider != null) { // ensure that BC can be used if necessary:
                request = new DefaultDecryptionKeyRequest<>(request.getPayload(), curveProvider,
                        ensureSecureRandom(request), request.getHeader(), request.getEncryptionAlgorithm(),
                        request.getKey());
            }
        }

        final SecretKey derived = deriveKey(request, epk.toKey(), privateKey);

        DecryptionKeyRequest<SecretKey> unwrapReq =
                new DefaultDecryptionKeyRequest<>(request.getPayload(), request.getProvider(),
                        request.getSecureRandom(), header, request.getEncryptionAlgorithm(), derived);

        return WRAP_ALG.getDecryptionKey(unwrapReq);
    }
}
