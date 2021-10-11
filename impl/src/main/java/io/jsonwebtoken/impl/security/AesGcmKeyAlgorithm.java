package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.JweHeader;
import io.jsonwebtoken.impl.lang.Bytes;
import io.jsonwebtoken.impl.lang.CheckedFunction;
import io.jsonwebtoken.impl.lang.ValueGetter;
import io.jsonwebtoken.io.Encoders;
import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.security.KeyAlgorithm;
import io.jsonwebtoken.security.KeyRequest;
import io.jsonwebtoken.security.KeyResult;
import io.jsonwebtoken.security.SecurityException;
import io.jsonwebtoken.security.SymmetricAeadAlgorithm;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import java.security.Key;
import java.security.spec.AlgorithmParameterSpec;

/**
 * @since JJWT_RELEASE_VERSION
 */
public class AesGcmKeyAlgorithm extends AesAlgorithm implements KeyAlgorithm<SecretKey, SecretKey> {

    public static final String TRANSFORMATION = "AES/GCM/NoPadding";

    public AesGcmKeyAlgorithm(int keyLen) {
        super("A" + keyLen + "GCMKW", TRANSFORMATION, keyLen);
    }

    @Override
    public KeyResult getEncryptionKey(final KeyRequest<SecretKey, SecretKey> request) throws SecurityException {

        Assert.notNull(request, "request cannot be null.");
        final SecretKey kek = assertKey(request);
        SymmetricAeadAlgorithm enc = Assert.notNull(request.getEncryptionAlgorithm(), "Request encryptionAlgorithm cannot be null.");
        final SecretKey cek = Assert.notNull(enc.generateKey(), "Request encryption algorithm cannot generate a null key.");
        final byte[] iv = ensureInitializationVector(request);
        final AlgorithmParameterSpec ivSpec = getIvSpec(iv);

        byte[] taggedCiphertext = execute(request, Cipher.class, new CheckedFunction<Cipher, byte[]>() {
            @Override
            public byte[] apply(Cipher cipher) throws Exception {
                cipher.init(Cipher.WRAP_MODE, kek, ivSpec);
                return cipher.wrap(cek);
            }
        });

        int tagByteLength = this.tagBitLength / Byte.SIZE;
        // When using GCM mode, the JDK appends the authentication tag to the ciphertext, so let's extract it:
        int ciphertextLength = taggedCiphertext.length - tagByteLength;
        byte[] ciphertext = new byte[ciphertextLength];
        System.arraycopy(taggedCiphertext, 0, ciphertext, 0, ciphertextLength);
        byte[] tag = new byte[tagByteLength];
        System.arraycopy(taggedCiphertext, ciphertextLength, tag, 0, tagByteLength);

        String encodedIv = Encoders.BASE64URL.encode(iv);
        String encodedTag = Encoders.BASE64URL.encode(tag);
        request.getHeader().put("iv", encodedIv);
        request.getHeader().put("tag", encodedTag);

        return new DefaultKeyResult(cek, ciphertext);
    }

    @Override
    public SecretKey getDecryptionKey(KeyRequest<byte[], SecretKey> request) throws SecurityException {
        Assert.notNull(request, "request cannot be null.");
        final SecretKey kek = assertKey(request);
        final byte[] cekBytes = Assert.notEmpty(request.getPayload(), "Decryption request payload (ciphertext) cannot be null or empty.");
        final JweHeader header = Assert.notNull(request.getHeader(), "Request JweHeader cannot be null.");
        final ValueGetter getter = new DefaultValueGetter(header);
        final byte[] tag = getter.getRequiredBytes("tag", this.tagBitLength / Byte.SIZE);
        final byte[] iv = getter.getRequiredBytes("iv", this.ivBitLength / Byte.SIZE);
        final AlgorithmParameterSpec ivSpec = getIvSpec(iv);

        //for tagged GCM, the JCA spec requires that the tag be appended to the end of the ciphertext byte array:
        final byte[] taggedCiphertext = Bytes.concat(cekBytes, tag);

        return execute(request, Cipher.class, new CheckedFunction<Cipher, SecretKey>() {
            @Override
            public SecretKey apply(Cipher cipher) throws Exception {
                cipher.init(Cipher.UNWRAP_MODE, kek, ivSpec);
                Key key = cipher.unwrap(taggedCiphertext, KEY_ALG_NAME, Cipher.SECRET_KEY);
                Assert.state(key instanceof SecretKey, "cipher.unwrap must produce a SecretKey instance.");
                return (SecretKey) key;
            }
        });
    }
}
