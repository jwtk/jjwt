package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.JweHeader;
import io.jsonwebtoken.security.DecryptionKeyResolver;

import java.security.Key;

/**
 * @since JJWT_RELEASE_VERSION
 */
public class DisabledDecryptionKeyResolver implements DecryptionKeyResolver {

    /**
     * Singleton instance that may be used if direct instantiation is not desired.
     */
    public static final DisabledDecryptionKeyResolver INSTANCE = new DisabledDecryptionKeyResolver();

    @Override
    public Key resolveDecryptionKey(JweHeader header) {
        return null;
    }
}
