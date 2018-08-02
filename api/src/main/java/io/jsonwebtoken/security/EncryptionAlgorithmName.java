package io.jsonwebtoken.security;

/**
 * @since JJWT_RELEASE_VERSION
 */
public enum EncryptionAlgorithmName {

    A128CBC_HS256("A128CBC-HS256", "AES_128_CBC_HMAC_SHA_256 authenticated encryption algorithm, as defined in https://tools.ietf.org/html/rfc7518#section-5.2.3", "AES/CBC/PKCS5Padding"),
    A192CBC_HS384("A192CBC-HS384", "AES_192_CBC_HMAC_SHA_384 authenticated encryption algorithm, as defined in https://tools.ietf.org/html/rfc7518#section-5.2.4", "AES/CBC/PKCS5Padding"),
    A256CBC_HS512("A256CBC-HS512", "AES_256_CBC_HMAC_SHA_512 authenticated encryption algorithm, as defined in https://tools.ietf.org/html/rfc7518#section-5.2.5", "AES/CBC/PKCS5Padding"),
    A128GCM("A128GCM", "AES GCM using 128-bit key", "AES/GCM/NoPadding"),
    A192GCM("A192GCM", "AES GCM using 192-bit key", "AES/GCM/NoPadding"),
    A256GCM("A256GCM", "AES GCM using 256-bit key", "AES/GCM/NoPadding");

    private final String name;
    private final String description;
    private final String jcaName;

    EncryptionAlgorithmName(String name, String description, String jcaName) {
        this.name = name;
        this.description = description;
        this.jcaName = jcaName;
    }

    /**
     * Returns the JWA algorithm name constant.
     *
     * @return the JWA algorithm name constant.
     */
    public String getValue() {
        return name;
    }

    /**
     * Returns the JWA algorithm description.
     *
     * @return the JWA algorithm description.
     */
    public String getDescription() {
        return description;
    }

    /**
     * Returns the name of the JCA algorithm used to encrypt or decrypt JWE content.
     *
     * @return the name of the JCA algorithm used to encrypt or decrypt JWE content.
     */
    public String getJcaName() {
        return jcaName;
    }

    /**
     * Returns the corresponding {@code EncryptionAlgorithmName} enum instance based on a
     * case-<em>insensitive</em> name comparison of the specified JWE <code>enc</code> value.
     *
     * @param name the case-insensitive JWE <code>enc</code> header value.
     * @return Returns the corresponding {@code EncryptionAlgorithmName} enum instance based on a
     * case-<em>insensitive</em> name comparison of the specified JWE <code>enc</code> value.
     * @throws IllegalArgumentException if the specified value does not match any JWE {@code EncryptionAlgorithmName} value.
     */
    public static EncryptionAlgorithmName forName(String name) throws IllegalArgumentException {
        for (EncryptionAlgorithmName enc : values()) {
            if (enc.getValue().equalsIgnoreCase(name)) {
                return enc;
            }
        }

        throw new IllegalArgumentException("Unsupported JWE Content Encryption Algorithm name: " + name);
    }

    @Override
    public String toString() {
        return name;
    }
}
