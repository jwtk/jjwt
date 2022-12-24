package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.impl.lang.CheckedFunction;
import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.security.DecryptionKeyRequest;
import io.jsonwebtoken.security.KeyAlgorithm;
import io.jsonwebtoken.security.KeyRequest;
import io.jsonwebtoken.security.KeyResult;
import io.jsonwebtoken.security.SecurityException;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.AlgorithmParameterSpec;

/**
 * @since JJWT_RELEASE_VERSION
 */
public class DefaultRsaKeyAlgorithm extends CryptoAlgorithm implements KeyAlgorithm<PublicKey, PrivateKey> {

    private final AlgorithmParameterSpec SPEC; //can be null

    public DefaultRsaKeyAlgorithm(String id, String jcaTransformationString) {
        this(id, jcaTransformationString, null);
    }

    public DefaultRsaKeyAlgorithm(String id, String jcaTransformationString, AlgorithmParameterSpec spec) {
        super(id, jcaTransformationString);
        this.SPEC = spec; //can be null
    }

    @Override
    public KeyResult getEncryptionKey(final KeyRequest<PublicKey> request) throws SecurityException {
        Assert.notNull(request, "Request cannot be null.");
        final PublicKey kek = Assert.notNull(request.getKey(), "Request key encryption key cannot be null.");
        final SecretKey cek = generateKey(request);

        byte[] ciphertext = execute(request, Cipher.class, new CheckedFunction<Cipher, byte[]>() {
            @Override
            public byte[] apply(Cipher cipher) throws Exception {
                if (SPEC == null) {
                    cipher.init(Cipher.WRAP_MODE, kek, ensureSecureRandom(request));
                } else {
                    cipher.init(Cipher.WRAP_MODE, kek, SPEC, ensureSecureRandom(request));
                }
                return cipher.wrap(cek);
            }
        });

        return new DefaultKeyResult(cek, ciphertext);
    }

    @Override
    public SecretKey getDecryptionKey(DecryptionKeyRequest<PrivateKey> request) throws SecurityException {
        Assert.notNull(request, "request cannot be null.");
        final PrivateKey kek = Assert.notNull(request.getKey(), "Request key decryption key cannot be null.");
        final byte[] cekBytes = Assert.notEmpty(request.getContent(), "Request content (encrypted key) cannot be null or empty.");

        return execute(request, Cipher.class, new CheckedFunction<Cipher, SecretKey>() {
            @Override
            public SecretKey apply(Cipher cipher) throws Exception {
                if (SPEC == null) {
                    cipher.init(Cipher.UNWRAP_MODE, kek);
                } else {
                    cipher.init(Cipher.UNWRAP_MODE, kek, SPEC);
                }
                Key key = cipher.unwrap(cekBytes, AesAlgorithm.KEY_ALG_NAME, Cipher.SECRET_KEY);
                Assert.state(key instanceof SecretKey, "Cipher unwrap must return a SecretKey instance.");
                return (SecretKey) key;
            }
        });
    }
}