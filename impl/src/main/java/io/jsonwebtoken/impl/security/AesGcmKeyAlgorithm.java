package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.JweHeader;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.io.Encoders;
import io.jsonwebtoken.lang.Arrays;
import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.lang.Maps;
import io.jsonwebtoken.security.EncryptedKeyAlgorithm;
import io.jsonwebtoken.security.KeyRequest;
import io.jsonwebtoken.security.KeyResult;
import io.jsonwebtoken.security.SecurityException;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import java.security.Key;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Map;

/**
 * @since JJWT_RELEASE_VERSION
 */
public class AesGcmKeyAlgorithm extends AesAlgorithm implements EncryptedKeyAlgorithm<SecretKey, SecretKey> {

    public static final String TRANSFORMATION = "AES/GCM/NoPadding";

    public AesGcmKeyAlgorithm(int keyLen) {
        super("A" + keyLen + "GCMKW", TRANSFORMATION, keyLen);
    }

    @Override
    public KeyResult getEncryptionKey(final KeyRequest<SecretKey, SecretKey> request) throws SecurityException {

        Assert.notNull(request, "request cannot be null.");
        final SecretKey kek = assertKey(request);
        final SecretKey cek = Assert.notNull(request.getPayload(), "Request content encryption key (request.getPayload()) cannot be null.");
        final byte[] iv = ensureInitializationVector(request);
        final AlgorithmParameterSpec ivSpec = getIvSpec(iv);

        byte[] taggedCiphertext = execute(request, Cipher.class, new InstanceCallback<Cipher, byte[]>() {
            @Override
            public byte[] doWithInstance(Cipher cipher) throws Exception {
                cipher.init(Cipher.WRAP_MODE, kek, ivSpec);
                return cipher.wrap(cek);
            }
        });

        int tagByteLength = this.tagLength / Byte.SIZE;
        // When using GCM mode, the JDK appends the authentication tag to the ciphertext, so let's extract it:
        int ciphertextLength = taggedCiphertext.length - tagByteLength;
        byte[] ciphertext = new byte[ciphertextLength];
        System.arraycopy(taggedCiphertext, 0, ciphertext, 0, ciphertextLength);
        byte[] tag = new byte[tagByteLength];
        System.arraycopy(taggedCiphertext, ciphertextLength, tag, 0, tagByteLength);

        String encodedIv = Encoders.BASE64URL.encode(iv);
        String encodedTag = Encoders.BASE64URL.encode(tag);
        Map<String,String> extraParams = Maps.of("iv", encodedIv).and("tag", encodedTag).build();

        return new DefaultKeyResult(ciphertext, cek, extraParams);
    }

    @Override
    public SecretKey getDecryptionKey(KeyRequest<byte[], SecretKey> request) throws SecurityException {
        Assert.notNull(request, "request cannot be null.");
        final SecretKey kek = assertKey(request);
        final byte[] cekBytes = Assert.notEmpty(request.getPayload(), "Decryption request payload (ciphertext) cannot be null or empty.");
        final JweHeader header = Assert.notNull(request.getHeader(), "Request JweHeader cannot be null.");
        final byte[] tag = getHeaderByteArray(header, "tag", this.tagLength / Byte.SIZE);
        final byte[] iv = getHeaderByteArray(header, "iv", this.ivLength / Byte.SIZE);
        final AlgorithmParameterSpec ivSpec = getIvSpec(iv);

        //for tagged GCM, the JCA spec requires that the tag be appended to the end of the ciphertext byte array:
        final byte[] taggedCiphertext = plus(cekBytes, tag);

        return execute(request, Cipher.class, new InstanceCallback<Cipher, SecretKey>() {
            @Override
            public SecretKey doWithInstance(Cipher cipher) throws Exception {
                cipher.init(Cipher.UNWRAP_MODE, kek, ivSpec);
                Key key = cipher.unwrap(taggedCiphertext, KEY_ALG_NAME, Cipher.SECRET_KEY);
                Assert.state(key instanceof SecretKey, "cipher.unwrap must produce a SecretKey instance.");
                return (SecretKey)key;
            }
        });
    }

    private byte[] getHeaderByteArray(JweHeader header, String name, int requiredByteLength) {
        Object value = header.get(name);
        if (value == null) {
            String msg = "The " + getId() + " Key Management Algorithm requires a JweHeader '" + name + "' value.";
            throw new MalformedJwtException(msg);
        }
        if (!(value instanceof String)) {
            String msg = "The " + getId() + " Key Management Algorithm requires the JweHeader '" + name + "' value to be a Base64URL-encoded String. Actual type: " + value.getClass().getName();
            throw new MalformedJwtException(msg);
        }
        String encoded = (String)value;

        byte[] decoded;
        try {
            decoded = Decoders.BASE64URL.decode(encoded);
        } catch (Exception e) {
            String msg = "JweHeader '" + name + "' value '" + encoded +
                "' does not appear to be a valid Base64URL String: " + e.getMessage();
            throw new MalformedJwtException(msg, e);
        }

        int len = Arrays.length(decoded);
        if (len != requiredByteLength) {
            String msg = "The '" + getId() + "' key management algorithm requires the JweHeader '" + name +
                "' value to be " + (requiredByteLength * Byte.SIZE) + " bits (" + requiredByteLength +
                " bytes) in length. Actual length: " + (len * Byte.SIZE) + " bits (" + len + " bytes).";
            throw new MalformedJwtException(msg);
        }

        return decoded;
    }
}
