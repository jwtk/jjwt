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
import io.jsonwebtoken.security.Request;
import io.jsonwebtoken.security.SecurityException;

import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.ECKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;

/**
 * @since JJWT_RELEASE_VERSION
 */
class EcdhKeyAlgorithm extends CryptoAlgorithm implements KeyAlgorithm<PublicKey, PrivateKey> {

    protected static final String JCA_NAME = "ECDH";
    protected static final String DEFAULT_ID = JCA_NAME + "-ES";

    // Per https://www.rfc-editor.org/rfc/rfc7518.html#section-4.6.2, 2nd paragraph:
    //    Key derivation is performed using the Concat KDF, as defined in
    //    Section 5.8.1 of [NIST.800-56A](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-56Ar2.pdf),
    //    where the Digest Method is SHA-256.
    private static final String CONCAT_KDF_HASH_ALG_NAME = "SHA-256";
    private static final ConcatKDF CONCAT_KDF = new ConcatKDF(CONCAT_KDF_HASH_ALG_NAME);
    public static final String KEK_ECKEY_TYPE_MESSAGE = "Key Encryption Key must implement " + ECKey.class.getName() + ".";
    public static final String KDK_ECKEY_TYPE_MESSAGE = "Key Decryption Key must implement " + ECKey.class.getName() + ".";

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

    //visible for testing
    protected KeyPair generateKeyPair(final Request request, final ECParameterSpec spec) {
        Assert.notNull(spec, "request key params cannot be null.");
        JcaTemplate template = new JcaTemplate(ECCurve.KEY_PAIR_GENERATOR_JCA_NAME, getProvider(request), ensureSecureRandom(request));
        return template.generateKeyPair(spec);
    }

    protected byte[] generateZ(final KeyRequest<?> request, final PublicKey pub, final PrivateKey priv) {
        return execute(request, KeyAgreement.class, new CheckedFunction<KeyAgreement, byte[]>() {
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
    public KeyResult getEncryptionKey(KeyRequest<PublicKey> request) throws SecurityException {
        Assert.notNull(request, "Request cannot be null.");
        JweHeader header = Assert.notNull(request.getHeader(), "Request JweHeader cannot be null.");

        PublicKey publicKey = Assert.notNull(request.getKey(), "Request key cannot be null.");
        ECKey ecPublicKey = Assert.isInstanceOf(ECKey.class, publicKey, KEK_ECKEY_TYPE_MESSAGE);

        ECParameterSpec spec = Assert.notNull(ecPublicKey.getParams(), "Request key params cannot be null.");
        // note: we don't need to validate if specified key's point is on a supported curve here
        // because that will automatically be asserted when using Jwks.builder().... below
        KeyPair pair = generateKeyPair(request, spec);
        ECPublicKey genPubKey = KeyPairs.getKey(pair, ECPublicKey.class);
        ECPrivateKey genPrivKey = KeyPairs.getKey(pair, ECPrivateKey.class);
        // This asserts that the generated public key (and therefore the request key) is on a JWK-supported curve:
        final EcPublicJwk jwk = Jwks.builder().forKey(genPubKey).build();

        final SecretKey derived = deriveKey(request, publicKey, genPrivKey);

        DefaultKeyRequest<SecretKey> wrapReq = new DefaultKeyRequest<>(request.getProvider(), request.getSecureRandom(),
                derived, request.getHeader(), request.getEncryptionAlgorithm());
        KeyResult result = WRAP_ALG.getEncryptionKey(wrapReq);

        header.put(DefaultJweHeader.EPK.getId(), jwk);

        return result;
    }

    @Override
    public SecretKey getDecryptionKey(DecryptionKeyRequest<PrivateKey> request) throws SecurityException {

        Assert.notNull(request, "Request cannot be null.");
        JweHeader header = Assert.notNull(request.getHeader(), "Request JweHeader cannot be null.");
        PrivateKey privateKey = Assert.notNull(request.getKey(), "Request key cannot be null.");
        ECKey ecPrivateKey = Assert.isInstanceOf(ECKey.class, privateKey, KDK_ECKEY_TYPE_MESSAGE);

        FieldReadable reader = new RequiredFieldReader(header);
        EcPublicJwk epk = reader.get(DefaultJweHeader.EPK);

        // While the EPK might be on a JWA-supported NIST curve, it must be on the private key's exact curve:
        if (!EcPublicJwkFactory.contains(ecPrivateKey.getParams().getCurve(), epk.toKey().getW())) {
            String msg = "JWE Header " + DefaultJweHeader.EPK + " value does not represent " +
                    "a point on the expected curve.";
            throw new InvalidKeyException(msg);
        }

        final SecretKey derived = deriveKey(request, epk.toKey(), privateKey);

        DecryptionKeyRequest<SecretKey> unwrapReq = new DefaultDecryptionKeyRequest<>(request.getProvider(),
                request.getSecureRandom(), derived, header, request.getEncryptionAlgorithm(), request.getContent());

        return WRAP_ALG.getDecryptionKey(unwrapReq);
    }
}
