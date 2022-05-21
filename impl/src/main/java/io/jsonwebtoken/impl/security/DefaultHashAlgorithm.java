package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.impl.lang.CheckedFunction;

import java.security.MessageDigest;

class DefaultHashAlgorithm extends CryptoAlgorithm implements HashAlgorithm {

    static final HashAlgorithm SHA1 = new DefaultHashAlgorithm("SHA1", "SHA-1");
    static final HashAlgorithm SHA256 = new DefaultHashAlgorithm("SHA256", "SHA-256");

    DefaultHashAlgorithm(String id, String jcaName) {
        super(id, jcaName);
    }

    @Override
    public byte[] hash(final ContentRequest request) {
        return execute(request, MessageDigest.class, new CheckedFunction<MessageDigest, byte[]>() {
            @Override
            public byte[] apply(MessageDigest md) {
                return md.digest(request.getContent());
            }
        });
    }
}
