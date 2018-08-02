package io.jsonwebtoken.security;

import io.jsonwebtoken.lang.Collections;

import java.util.List;

/**
 * Type-safe representation of standard JWE encryption key management algorithm names as defined in the
 * <a href="https://tools.ietf.org/html/rfc7518">JSON Web Algorithms</a> specification.
 *
 * @since JJWT_RELEASE_VERSION
 */
public enum KeyManagementAlgorithmName {

    RSA1_5("RSA1_5", "RSAES-PKCS1-v1_5", Collections.<String>emptyList(), "RSA/ECB/PKCS1Padding"),
    RSA_OAEP("RSA-OAEP", "RSAES OAEP using default parameters", Collections.<String>emptyList(), "RSA/ECB/OAEPWithSHA-1AndMGF1Padding"),
    RSA_OAEP_256("RSA-OAEP-256", "RSAES OAEP using SHA-256 and MGF1 with SHA-256", Collections.<String>emptyList(), "RSA/ECB/OAEPWithSHA-256AndMGF1Padding & MGF1ParameterSpec.SHA256"),
    A128KW("A128KW", "AES Key Wrap with default initial value using 128-bit key", Collections.<String>emptyList(), "AESWrap"),
    A192KW("A192KW", "AES Key Wrap with default initial value using 192-bit key", Collections.<String>emptyList(), "AESWrap"),
    A256KW("A256KW", "AES Key Wrap with default initial value using 256-bit key", Collections.<String>emptyList(), "AESWrap"),
    dir("dir", "Direct use of a shared symmetric key as the CEK", Collections.<String>emptyList(), "RSA/ECB/OAEPWithSHA-1AndMGF1Padding"),
    ECDH_ES("ECDH-ES", "Elliptic Curve Diffie-Hellman Ephemeral Static key agreement using Concat KDF", Collections.of("epk", "apu", "apv"), "ECDH"),
    ECDH_ES_A128KW("ECDH-ES+A128KW", "ECDH-ES using Concat KDF and CEK wrapped with \"A128KW\"", Collections.of("epk", "apu", "apv"), "ECDH???"),
    ECDH_ES_A192KW("ECDH-ES+A192KW", "ECDH-ES using Concat KDF and CEK wrapped with \"A192KW\"", Collections.of("epk", "apu", "apv"), "ECDH???"),
    ECDH_ES_A256KW("ECDH-ES+A256KW", "ECDH-ES using Concat KDF and CEK wrapped with \"A256KW\"", Collections.of("epk", "apu", "apv"), "ECDH???"),
    A128GCMKW("A128GCMKW", "Key wrapping with AES GCM using 128-bit key", Collections.of("iv", "tag"), "???"),
    A192GCMKW("A192GCMKW", "Key wrapping with AES GCM using 192-bit key", Collections.of("iv", "tag"), "???"),
    A256GCMKW("A256GCMKW", "Key wrapping with AES GCM using 256-bit key", Collections.of("iv", "tag"), "???"),
    PBES2_HS256_A128KW("PBES2-HS256+A128KW", "PBES2 with HMAC SHA-256 and \"A128KW\" wrapping", Collections.of("p2s", "p2c"), "???"),
    PBES2_HS384_A192KW("PBES2-HS384+A192KW", "PBES2 with HMAC SHA-384 and \"A192KW\" wrapping", Collections.of("p2s", "p2c"), "???"),
    PBES2_HS512_A256KW("PBES2-HS512+A256KW", "PBES2 with HMAC SHA-512 and \"A256KW\" wrapping", Collections.of("p2s", "p2c"), "???");

    private final String value;
    private final String description;
    private final List<String> moreHeaderParams;
    private final String jcaName;

    KeyManagementAlgorithmName(String value, String description, List<String> moreHeaderParams, String jcaName) {
        this.value = value;
        this.description = description;
        this.moreHeaderParams = moreHeaderParams;
        this.jcaName = jcaName;
    }

    /**
     * Returns the JWA algorithm name constant.
     *
     * @return the JWA algorithm name constant.
     */
    public String getValue() {
        return value;
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
     * Returns a list of header parameters that must exist in the JWE header when evaluating the key management
     * algorithm.  The list will be empty for algorithms that do not require additional header parameters.
     *
     * @return a list of header parameters that must exist in the JWE header when evaluating the key management
     * algorithm.
     */
    public List<String> getMoreHeaderParams() {
        return moreHeaderParams;
    }

    /**
     * Returns the name of the JCA algorithm used to create or validate the Content Encryption Key (CEK).
     *
     * @return the name of the JCA algorithm used to create or validate the Content Encryption Key (CEK).
     */
    public String getJcaName() {
        return jcaName;
    }

    /**
     * Returns the corresponding {@code KeyManagementAlgorithmName} enum instance based on a
     * case-<em>insensitive</em> name comparison of the specified JWE <code>alg</code> value.
     *
     * @param name the case-insensitive JWE <code>alg</code> header value.
     * @return Returns the corresponding {@code KeyManagementAlgorithmName} enum instance based on a
     * case-<em>insensitive</em> name comparison of the specified JWE <code>alg</code> value.
     * @throws IllegalArgumentException if the specified value does not match any JWE {@code KeyManagementAlgorithmName} value.
     */
    public static KeyManagementAlgorithmName forName(String name) throws IllegalArgumentException {
        for (KeyManagementAlgorithmName alg : values()) {
            if (alg.getValue().equalsIgnoreCase(name)) {
                return alg;
            }
        }

        throw new IllegalArgumentException("Unsupported JWE Key Management Algorithm name: " + name);
    }

    @Override
    public String toString() {
        return value;
    }
}
