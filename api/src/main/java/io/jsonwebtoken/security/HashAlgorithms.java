package io.jsonwebtoken.security;

public final class HashAlgorithms {

    //prevent instantiation
    private HashAlgorithms() {}

    private static HashAlgorithm forJcaName(final String jcaName) {
        //TODO: IMPLEMENT ME
        return new HashAlgorithm() {
            @Override
            public String getId() {
                return jcaName;
            }
        };
    }
    public static final HashAlgorithm MD5 = forJcaName("MD5");
    public static final HashAlgorithm SHA_1 = forJcaName("SHA-1");
    public static final HashAlgorithm SHA_256 = forJcaName("SHA-256");
}
