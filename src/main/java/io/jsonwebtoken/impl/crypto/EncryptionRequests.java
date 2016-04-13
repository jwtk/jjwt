package io.jsonwebtoken.impl.crypto;

public final class EncryptionRequests {

    //100% code coverage
    private static final EncryptionRequests INSTANCE = new EncryptionRequests();

    private EncryptionRequests(){} //prevent instantiation

    public static EncryptionRequestBuilder builder() {
        return new DefaultEncryptionRequestBuilder();
    }
}
