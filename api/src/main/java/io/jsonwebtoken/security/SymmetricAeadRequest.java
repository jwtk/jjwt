package io.jsonwebtoken.security;

import javax.crypto.SecretKey;

/**
 * @since JJWT_RELEASE_VERSION
 */
public interface SymmetricAeadRequest extends CryptoRequest<byte[], SecretKey>, AssociatedDataSupplier {
}
