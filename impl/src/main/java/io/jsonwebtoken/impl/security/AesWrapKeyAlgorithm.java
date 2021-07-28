package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.security.EncryptedKeyAlgorithm;
import io.jsonwebtoken.security.KeyRequest;
import io.jsonwebtoken.security.KeyResult;
import io.jsonwebtoken.security.SecurityException;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import java.security.Key;

/**
 * @since JJWT_RELEASE_VERSION
 */
public class AesWrapKeyAlgorithm extends AesAlgorithm implements EncryptedKeyAlgorithm<SecretKey, SecretKey> {

    private static final String TRANSFORMATION = "AESWrap";

    public AesWrapKeyAlgorithm(int keyLen) {
        super("A" + keyLen + "KW", TRANSFORMATION, keyLen);
    }

    @Override
    public KeyResult getEncryptionKey(KeyRequest<SecretKey, SecretKey> request) throws SecurityException {
        Assert.notNull(request, "request cannot be null.");
        final SecretKey kek = assertKey(request);
        final SecretKey cek = Assert.notNull(request.getPayload(), "Request content encryption key (request.getPayload()) cannot be null.");

        byte[] ciphertext = execute(request, Cipher.class, new InstanceCallback<Cipher, byte[]>() {
            @Override
            public byte[] doWithInstance(Cipher cipher) throws Exception {
                cipher.init(Cipher.WRAP_MODE, kek);
                return cipher.wrap(cek);
            }
        });

        return new DefaultKeyResult(ciphertext, cek);
    }

    @Override
    public SecretKey getDecryptionKey(KeyRequest<byte[], SecretKey> request) throws SecurityException {
        Assert.notNull(request, "request cannot be null.");
        final SecretKey kek = assertKey(request);
        final byte[] cekBytes = Assert.notEmpty(request.getPayload(), "Request encrypted key (request.getPayload()) cannot be null or empty.");

        return execute(request, Cipher.class, new InstanceCallback<Cipher, SecretKey>() {
            @Override
            public SecretKey doWithInstance(Cipher cipher) throws Exception {
                cipher.init(Cipher.UNWRAP_MODE, kek);
                Key key = cipher.unwrap(cekBytes, KEY_ALG_NAME, Cipher.SECRET_KEY);
                Assert.state(key instanceof SecretKey, "Cipher unwrap must return a SecretKey instance.");
                return (SecretKey) key;
            }
        });
    }
}
