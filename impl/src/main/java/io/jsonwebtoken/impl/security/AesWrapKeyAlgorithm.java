package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.impl.lang.CheckedFunction;
import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.security.DecryptionKeyRequest;
import io.jsonwebtoken.security.KeyRequest;
import io.jsonwebtoken.security.KeyResult;
import io.jsonwebtoken.security.SecretKeyAlgorithm;
import io.jsonwebtoken.security.SecurityException;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import java.security.Key;

/**
 * @since JJWT_RELEASE_VERSION
 */
public class AesWrapKeyAlgorithm extends AesAlgorithm implements SecretKeyAlgorithm {

    private static final String TRANSFORMATION = "AESWrap";

    public AesWrapKeyAlgorithm(int keyLen) {
        super("A" + keyLen + "KW", TRANSFORMATION, keyLen);
    }

    @Override
    public KeyResult getEncryptionKey(KeyRequest<SecretKey> request) throws SecurityException {
        Assert.notNull(request, "request cannot be null.");
        final SecretKey kek = assertKey(request.getPayload());
        final SecretKey cek = generateKey(request);

        byte[] ciphertext = execute(request, Cipher.class, new CheckedFunction<Cipher, byte[]>() {
            @Override
            public byte[] apply(Cipher cipher) throws Exception {
                cipher.init(Cipher.WRAP_MODE, kek);
                return cipher.wrap(cek);
            }
        });

        return new DefaultKeyResult(cek, ciphertext);
    }

    @Override
    public SecretKey getDecryptionKey(DecryptionKeyRequest<SecretKey> request) throws SecurityException {
        Assert.notNull(request, "request cannot be null.");
        final SecretKey kek = assertKey(request.getKey());
        final byte[] cekBytes = Assert.notEmpty(request.getPayload(), "Request content (encrypted key) cannot be null or empty.");

        return execute(request, Cipher.class, new CheckedFunction<Cipher, SecretKey>() {
            @Override
            public SecretKey apply(Cipher cipher) throws Exception {
                cipher.init(Cipher.UNWRAP_MODE, kek);
                Key key = cipher.unwrap(cekBytes, KEY_ALG_NAME, Cipher.SECRET_KEY);
                Assert.state(key instanceof SecretKey, "Cipher unwrap must return a SecretKey instance.");
                return (SecretKey) key;
            }
        });
    }
}
