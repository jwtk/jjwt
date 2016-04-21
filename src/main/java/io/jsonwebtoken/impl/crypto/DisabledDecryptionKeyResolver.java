package io.jsonwebtoken.impl.crypto;

import io.jsonwebtoken.DecryptionKeyResolver;
import io.jsonwebtoken.JweHeader;

import java.security.Key;

/**
 * @since 0.7.0
 */
public class DisabledDecryptionKeyResolver implements DecryptionKeyResolver {

    @Override
    public Key resolveDecryptionKey(JweHeader header) {
        return null;
    }
}
