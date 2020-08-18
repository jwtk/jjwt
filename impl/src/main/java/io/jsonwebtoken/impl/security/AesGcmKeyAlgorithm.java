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
import javax.crypto.spec.GCMParameterSpec;
import java.security.Key;
import java.security.SecureRandom;
import java.util.Map;

/**
 * @since JJWT_RELEASE_VERSION
 */
public class AesGcmKeyAlgorithm extends CryptoAlgorithm implements EncryptedKeyAlgorithm<SecretKey, SecretKey> {

    public static final String TRANSFORMATION = "AES/GCM/NoPadding";

    public AesGcmKeyAlgorithm(int keyLen) {
        super("A" + keyLen + "GCMKW", TRANSFORMATION);
        Assert.isTrue(keyLen == 128 || keyLen == 192 || keyLen == 256, "Invalid AES key length: it must equal 128, 192, or 256.");
    }

    @Override
    public KeyResult getEncryptionKey(KeyRequest<SecretKey, SecretKey> request) throws SecurityException {
        Assert.notNull(request, "request cannot be null.");
        final SecretKey kek = Assert.notNull(request.getKey(), "Request key encryption key (request.getKey()) cannot be null.");
        final SecretKey cek = Assert.notNull(request.getPayload(), "Request content encryption key (request.getPayload()) cannot be null.");

        final byte[] iv = new byte[12]; // GCM IV is 96 bits (12 bytes)
        SecureRandom random = ensureSecureRandom(request);
        random.nextBytes(iv);

        byte[] jcaResult = execute(request, Cipher.class, new InstanceCallback<Cipher, byte[]>() {
            @Override
            public byte[] doWithInstance(Cipher cipher) throws Exception {
                cipher.init(Cipher.WRAP_MODE, kek, new GCMParameterSpec(128, iv));
                return cipher.wrap(cek);
            }
        });

        //The JCA concatenates the ciphertext and the tag - split them:
        int ciphertextLength = jcaResult.length - 16; //16 == AES block size in bytes (128 bits)
        byte[] ciphertext = new byte[ciphertextLength];
        System.arraycopy(jcaResult, 0, ciphertext, 0, ciphertextLength);

        byte[] tag = new byte[16];
        System.arraycopy(jcaResult, ciphertextLength, tag, 0, 16);

        String encodedIv = Encoders.BASE64URL.encode(iv);
        String encodedTag = Encoders.BASE64URL.encode(tag);
        Map<String,String> extraParams = Maps.of("iv", encodedIv).and("tag", encodedTag).build();

        return new DefaultKeyResult(ciphertext, cek, extraParams);
    }

    private byte[] getHeaderByteArray(JweHeader header, String name, int requiredLength) {
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
        if (len != requiredLength) {
            String msg = "The '" + getId() + "' key management algorithm requires the JweHeader '" + name +
                "' value to be " + (requiredLength * Byte.SIZE) + " bits (" + requiredLength +
                " bytes) in length. Actual length: " + (len * Byte.SIZE) + " bits (" + len + " bytes).";
            throw new MalformedJwtException(msg);
        }

        return decoded;
    }

    @Override
    public SecretKey getDecryptionKey(KeyRequest<byte[], SecretKey> request) throws SecurityException {
        Assert.notNull(request, "request cannot be null.");
        final SecretKey kek = Assert.notNull(request.getKey(), "Request key decryption key (request.getKey()) cannot be null.");
        final byte[] cekBytes = Assert.notNull(request.getPayload(), "Request encrypted key (request.getPayload()) cannot be null.");
        Assert.isTrue(cekBytes.length > 0, "Request encrypted key (request.getPayload()) cannot be empty.");
        final JweHeader header = Assert.notNull(request.getHeader(), "Request JweHeader cannot be null.");

        final byte[] iv = getHeaderByteArray(header, "iv", 12);

        final byte[] tag = getHeaderByteArray(header, "tag", 16);

        // JCA api expects the ciphertext to have the format: encrypted_bytes + authentication_tag
        // so we need to reconstitute that format before passing in to the cipher:
        final byte[] ciphertext = new byte[cekBytes.length + tag.length];
        System.arraycopy(cekBytes, 0, ciphertext, 0, cekBytes.length);
        System.arraycopy(tag, 0, ciphertext, cekBytes.length, tag.length);

        return execute(request, Cipher.class, new InstanceCallback<Cipher, SecretKey>() {
            @Override
            public SecretKey doWithInstance(Cipher cipher) throws Exception {
                cipher.init(Cipher.UNWRAP_MODE, kek, new GCMParameterSpec(128, iv));
                Key key = cipher.unwrap(ciphertext, "AES", Cipher.SECRET_KEY);
                Assert.state(key instanceof SecretKey, "cipher.unwrap must produce a SecretKey instance.");
                return (SecretKey)key;
            }
        });
    }
}
