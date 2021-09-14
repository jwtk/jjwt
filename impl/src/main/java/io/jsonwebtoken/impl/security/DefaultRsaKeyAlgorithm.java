package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.security.EncryptedKeyAlgorithm;
import io.jsonwebtoken.security.KeyRequest;
import io.jsonwebtoken.security.KeyResult;
import io.jsonwebtoken.security.SecurityException;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAKey;
import java.security.spec.AlgorithmParameterSpec;

public class DefaultRsaKeyAlgorithm<EK extends RSAKey & PublicKey, DK extends RSAKey & PrivateKey> extends CryptoAlgorithm
    implements EncryptedKeyAlgorithm<EK, DK> {

    private final AlgorithmParameterSpec SPEC; //can be null

    public DefaultRsaKeyAlgorithm(String id, String jcaTransformationString) {
        this(id, jcaTransformationString, null);
    }

    public DefaultRsaKeyAlgorithm(String id, String jcaTransformationString, AlgorithmParameterSpec spec) {
        super(id, jcaTransformationString);
        this.SPEC = spec; //can be null
    }

    @Override
    public KeyResult getEncryptionKey(final KeyRequest<SecretKey, EK> request) throws SecurityException {
        Assert.notNull(request, "Request cannot be null.");
        final EK kek = Assert.notNull(request.getKey(), "Request key encryption key cannot be null.");
        final SecretKey cek = Assert.notNull(request.getPayload(), "Request content encryption key (request.getPayload() cannot be null.");

        byte[] ciphertext = execute(request, Cipher.class, new InstanceCallback<Cipher, byte[]>() {
            @Override
            public byte[] doWithInstance(Cipher cipher) throws Exception {
                if (SPEC == null) {
                    cipher.init(Cipher.WRAP_MODE, kek, ensureSecureRandom(request));
                } else {
                    cipher.init(Cipher.WRAP_MODE, kek, SPEC, ensureSecureRandom(request));
                }
                return cipher.wrap(cek);
            }
        });

        return new DefaultKeyResult(ciphertext, cek);
    }

    @Override
    public SecretKey getDecryptionKey(KeyRequest<byte[], DK> request) throws SecurityException {
        Assert.notNull(request, "request cannot be null.");
        final DK kek = Assert.notNull(request.getKey(), "Request key decryption key cannot be null.");
        final byte[] cekBytes = Assert.notEmpty(request.getPayload(), "Request encrypted key (request.getPayload()) cannot be null or empty.");

        return execute(request, Cipher.class, new InstanceCallback<Cipher, SecretKey>() {
            @Override
            public SecretKey doWithInstance(Cipher cipher) throws Exception {
                if (SPEC == null) {
                    cipher.init(Cipher.UNWRAP_MODE, kek);
                } else {
                    cipher.init(Cipher.UNWRAP_MODE, kek, SPEC);
                }
                Key key = cipher.unwrap(cekBytes, "AES", Cipher.SECRET_KEY);
                Assert.state(key instanceof SecretKey, "Cipher unwrap must return a SecretKey instance.");
                return (SecretKey) key;
            }
        });
    }
}