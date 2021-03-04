package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.Header;
import io.jsonwebtoken.JwsHeader;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.security.KeyResolver;

import java.security.Key;

public class StaticKeyResolver implements KeyResolver {

    private final Key signatureVerificationKey;
    private final Key decryptionKey;

    public StaticKeyResolver(Key signatureVerificationKey, Key decryptionKey) {
        this.signatureVerificationKey = signatureVerificationKey;
        this.decryptionKey = decryptionKey;
    }

    @Override
    public Key resolveKey(Header<?> header) {
        if (header instanceof JwsHeader) {
            if (this.signatureVerificationKey == null) {
                String msg = "Signed JWTs are not supported: the JwtParser has not been configured with a " +
                    "signature verification key or a KeyResolver. Consider configuring the JwtParserBuilder with " +
                    "one of these to ensure it can use the necessary key to verify JWS signatures.";
                throw new UnsupportedJwtException(msg);
            }
            return this.signatureVerificationKey;
        } else { // JweHeader
            if (this.decryptionKey == null) {
                String msg = "Encrypted JWTs are not supported: the JwtParser has not been configured with a " +
                    "decryption key or a KeyResolver. Consider configuring the JwtParserBuilder with " +
                    "one of these to ensure it can use the necessary key to decrypt JWEs.";
                throw new UnsupportedJwtException(msg);
            }
            return this.decryptionKey;
        }
    }
}
