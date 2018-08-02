package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.impl.lang.Services;
import io.jsonwebtoken.io.Decoder;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.io.Deserializer;
import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.security.EncryptionAlgorithm;
import io.jsonwebtoken.security.EncryptionAlgorithms;

import java.util.Map;

/**
 * @since JJWT_RELEASE_VERSION
 */
public class DefaultJweFactory {

    private final Decoder<String, byte[]> base64UrlDecoder;

    private final Deserializer<Map<String, Object>> deserializer;

    private final EncryptionAlgorithm encryptionAlgorithm;

    private static Deserializer<Map<String, Object>> loadDeserializer() {
        Deserializer deserializer = Services.loadFirst(Deserializer.class);
        //noinspection unchecked
        return (Deserializer<Map<String, Object>>) deserializer;
    }

    public DefaultJweFactory() {
        this(Decoders.BASE64URL, loadDeserializer(), EncryptionAlgorithms.A256GCM);
    }

    public DefaultJweFactory(Decoder<String, byte[]> base64UrlDecoder,
                             Deserializer<Map<String, Object>> deserializer,
                             EncryptionAlgorithm encryptionAlgorithm) {
        this.base64UrlDecoder = Assert.notNull(base64UrlDecoder, "Base64Url TextCodec cannot be null.");
        this.deserializer = Assert.notNull(deserializer, "Deserializer cannot be null.");
        this.encryptionAlgorithm = Assert.notNull(encryptionAlgorithm, "EncryptionAlgorithm cannot be null.");
    }

    /*

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

        final byte[] iv = base64UrlDecode(base64UrlIv, "Initialization Vector");

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
            return base64UrlDecoder.decode(base64UrlEncoded);
        } catch (Exception e) {
            String msg = "Invalid compact JWE: JWE " + jweName +
                " fragment is invalid and cannot be Base64Url-decoded: " + base64UrlEncoded;
            throw new IllegalArgumentException(msg, e);
        }
    }

    @SuppressWarnings("unchecked")
    protected Map<String, Object> parseJson(byte[] json) {
        return deserializer.deserialize(json);
    }

    */
}
