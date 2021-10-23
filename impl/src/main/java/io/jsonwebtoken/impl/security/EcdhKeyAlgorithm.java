package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.JweHeader;
import io.jsonwebtoken.impl.lang.CheckedFunction;
import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.security.DecryptionKeyRequest;
import io.jsonwebtoken.security.EcKeyAlgorithm;
import io.jsonwebtoken.security.EcPublicJwk;
import io.jsonwebtoken.security.Jwks;
import io.jsonwebtoken.security.KeyRequest;
import io.jsonwebtoken.security.KeyResult;
import io.jsonwebtoken.security.SecurityException;

import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.ECKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;

public class EcdhKeyAlgorithm<E extends ECKey & PublicKey, D extends ECKey & PrivateKey> extends CryptoAlgorithm implements EcKeyAlgorithm<E, D> {

    protected static final String JCA_NAME = "ECDH";
    protected static final String EPHEMERAL_PUBLIC_KEY = "epk";

    EcdhKeyAlgorithm(String id) {
        super(id, JCA_NAME);
    }

    private KeyPair generateKeyPair(final KeyRequest<E> request, final ECParameterSpec spec) {
        Assert.notNull(spec, "request key params cannot be null.");
        return new JcaTemplate("EC", request.getProvider(), ensureSecureRandom(request))
            .execute(KeyPairGenerator.class, new CheckedFunction<KeyPairGenerator, KeyPair>() {
            @Override
            public KeyPair apply(KeyPairGenerator keyPairGenerator) throws Exception {
                keyPairGenerator.initialize(spec, ensureSecureRandom(request));
                return keyPairGenerator.generateKeyPair();
            }
        });
    }

    protected SecretKey generateSecretKey(final KeyRequest<?> request, final PublicKey pub, final PrivateKey priv) {
        return execute(request, KeyAgreement.class, new CheckedFunction<KeyAgreement, SecretKey>() {
            @Override
            public SecretKey apply(KeyAgreement keyAgreement) throws Exception {
                keyAgreement.init(priv);
                keyAgreement.doPhase(pub, true);
                byte[] derived = keyAgreement.generateSecret();
                return new SecretKeySpec(derived, "AES");
            }
        });
    }

    @Override
    public KeyResult getEncryptionKey(KeyRequest<E> request) throws SecurityException {
        Assert.notNull(request, "Request cannot be null.");
        JweHeader header = Assert.notNull(request.getHeader(), "request JweHeader cannot be null.");
        E publicKey = Assert.notNull(request.getKey(), "request key cannot be null.");
        ECParameterSpec spec = Assert.notNull(publicKey.getParams(), "request key params cannot be null.");

        // note: we don't need to validate if specified key's point is on a supported curve here
        // because that will automatically be asserted when using Jwks.builder().... below

        KeyPair pair = generateKeyPair(request, spec);
        ECPublicKey genPubKey = KeyPairs.getKey(pair, ECPublicKey.class);
        ECPrivateKey genPrivKey = KeyPairs.getKey(pair, ECPrivateKey.class);

        SecretKey secretKey = generateSecretKey(request, publicKey, genPrivKey);

        // This line will assert/guarantee that the generated public key (and therefore the request key) is on
        // a JWK-supported curve:
        EcPublicJwk jwk = Jwks.builder().setKey(genPubKey).build();
        header.put(EPHEMERAL_PUBLIC_KEY, jwk);

        byte[] apu = header.getAgreementPartyUInfo();
        byte[] apv = header.getAgreementPartyVInfo();


        return null;
    }

    @Override
    public SecretKey getDecryptionKey(DecryptionKeyRequest<D> request) throws SecurityException {
        return null;
    }
}
