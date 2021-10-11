package io.jsonwebtoken.security;

import javax.crypto.SecretKey;

/**
 * @since JJWT_RELEASE_VERSION
 */
public interface KeyResult extends PayloadSupplier<byte[]>, KeySupplier<SecretKey> {
}
