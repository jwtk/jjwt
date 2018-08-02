package io.jsonwebtoken.security;

/**
 * An enum representing the {@code Key Management Mode} names defined in
 * <a href="https://tools.ietf.org/html/rfc7516#section-2">RFC 7516, Section 2</a>.
 *
 * @since JJWT_RELEASE_VERSION
 */
public enum KeyManagementModeName {

    KEY_ENCRYPTION("Key Encryption",
        "The CEK value is encrypted to the intended recipient using an asymmetric encryption algorithm"),

    KEY_WRAPPING("Key Wrapping",
        "The CEK value is encrypted to the intended recipient using a symmetric key wrapping algorithm."),

    DIRECT_KEY_AGREEMENT("Direct Key Agreement",
        "A key agreement algorithm is used to agree upon the CEK value."),

    KEY_AGREEMENT_WITH_KEY_WRAPPING("Key Agreement with Key Wrapping",
        "A key agreement algorithm is used to agree upon a symmetric key used to encrypt the CEK value to the " +
            "intended recipient using a symmetric key wrapping algorithm."),

    DIRECT_ENCRYPTION("Direct Encryption",
        "The CEK value used is the secret symmetric key value shared between the parties.");

    private final String name;
    private final String desc;

    KeyManagementModeName(String name, String desc) {
        this.name = name;
        this.desc = desc;
    }

    public String getName() {
        return name;
    }

    public String getDescription() {
        return desc;
    }
}
