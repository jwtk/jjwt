package io.jsonwebtoken.security;

import io.jsonwebtoken.Header;

import java.security.Key;

/**
 * @since JJWT_RELEASE_VERSION
 */
public interface KeyResolver {

    Key resolveKey(Header<?> header);
}
