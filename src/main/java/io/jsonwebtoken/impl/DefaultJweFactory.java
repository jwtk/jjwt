package io.jsonwebtoken.impl;

import io.jsonwebtoken.DecryptionKeyResolver;
import io.jsonwebtoken.EncryptionAlgorithms;
import io.jsonwebtoken.Jwe;
import io.jsonwebtoken.impl.crypto.DisabledDecryptionKeyResolver;
import io.jsonwebtoken.impl.crypto.EncryptionAlgorithm;
import io.jsonwebtoken.impl.serialization.JacksonSerializationCodec;
import io.jsonwebtoken.impl.serialization.SerializationCodec;
import io.jsonwebtoken.lang.Assert;

import java.util.Map;

public class DefaultJweFactory {

    private final TextCodec base64UrlCodec;

    private final SerializationCodec serializationCodec;

    private final EncryptionAlgorithm encryptionAlgorithm;

    private final DecryptionKeyResolver decryptionKeyResolver;

    public DefaultJweFactory() {
        this(TextCodec.BASE64URL, new JacksonSerializationCodec(), EncryptionAlgorithms.A256GCM, new DisabledDecryptionKeyResolver());
    }

    public DefaultJweFactory(TextCodec base64UrlCodec, SerializationCodec serializationCodec,
                             EncryptionAlgorithm encryptionAlgorithm, DecryptionKeyResolver decryptionKeyResolver) {
        Assert.notNull(base64UrlCodec, "Base64Url TextCodec cannot be null.");
        Assert.notNull(serializationCodec, "SerializationCodec cannot be null.");
        Assert.notNull(encryptionAlgorithm, "EncryptionAlgorithm cannot be null.");
        Assert.notNull(decryptionKeyResolver, "DecryptionKeyResolver cannot be null.");
        this.serializationCodec = serializationCodec;
        this.encryptionAlgorithm = encryptionAlgorithm;
        this.base64UrlCodec = base64UrlCodec;
        this.decryptionKeyResolver = decryptionKeyResolver;
    }

    public Jwe createJwe(String base64UrlProtectedHeader, String base64UrlEncryptedKey, String base64UrlIv,
                         String base64UrlCiphertext, String base64UrlAuthenticationTag) {

        // ====================================================================
        // https://tools.ietf.org/html/rfc7516#section-5.2 #2
        // ====================================================================

        final byte[] headerBytes = base64UrlDecode(base64UrlProtectedHeader, "Protected Header");

        // encrypted key can be null with Direct Key or Direct Key Agreement
        // https://tools.ietf.org/html/rfc7516#section-5.2
        // so we use a 'null safe' variant:
        final byte[] encryptedKeyBytes = nullSafeBase64UrlDecode(base64UrlEncryptedKey, "Encrypted Key");

        final byte[] iv = base64UrlDecode(base64UrlIv, "Initialization Value");

        final byte[] ciphertext = base64UrlDecode(base64UrlCiphertext, "Ciphertext");

        final byte[] authcTag = base64UrlDecode(base64UrlAuthenticationTag, "Authentication Tag");

        // ====================================================================
        // https://tools.ietf.org/html/rfc7516#section-5.2 #3
        // ====================================================================

        Map<String, Object> protectedHeader;
        try {
            protectedHeader = parseJson(headerBytes);
        } catch (Exception e) {
            String msg = "JWE Protected Header must be a valid JSON object.";
            throw new IllegalArgumentException(msg, e);
        }
        Assert.notEmpty(protectedHeader, "JWE Protected Header cannot be a null or empty JSON object.");

        DefaultJweHeader header = new DefaultJweHeader(protectedHeader);

        // ====================================================================
        // https://tools.ietf.org/html/rfc7516#section-5.2 #4
        // ====================================================================

        // we currently don't support JSON serialization (just compact), so we can skip #4

        // ====================================================================
        // https://tools.ietf.org/html/rfc7516#section-5.2 #11 and #12
        // ====================================================================


        throw new UnsupportedOperationException("Not yet finished.");

    }

    protected byte[] nullSafeBase64UrlDecode(String base64UrlEncoded, String jweName) {
        if (base64UrlEncoded == null) {
            return null;
        }
        return base64UrlDecode(base64UrlEncoded, jweName);
    }

    protected byte[] base64UrlDecode(String base64UrlEncoded, String jweName) {

        if (base64UrlEncoded == null) {
            String msg = "Invalid compact JWE: base64url JWE " + jweName + " is missing.";
            throw new IllegalArgumentException(msg);
        }

        try {
            return base64UrlCodec.decode(base64UrlEncoded);
        } catch (Exception e) {
            String msg = "Invalid compact JWE: JWE " + jweName +
                    " fragment is invalid and cannot be Base64Url-decoded: " + base64UrlEncoded;
            throw new IllegalArgumentException(msg, e);
        }
    }

    @SuppressWarnings("unchecked")
    protected Map<String, Object> parseJson(byte[] json) {
        return serializationCodec.deserialize(json, Map.class);
    }


}
