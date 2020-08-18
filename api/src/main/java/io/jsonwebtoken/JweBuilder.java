package io.jsonwebtoken;

import io.jsonwebtoken.security.KeyAlgorithm;
import io.jsonwebtoken.security.SymmetricAeadAlgorithm;

import javax.crypto.SecretKey;
import java.security.Key;

/**
 * @since JJWT_RELEASE_VERSION
 */
public interface JweBuilder extends JwtBuilder<JweBuilder> {

    JweBuilder encryptWith(SymmetricAeadAlgorithm enc);

    JweBuilder withKey(SecretKey key);

    <K extends Key> JweBuilder withKeyFrom(K key, KeyAlgorithm<K, ?> alg);
}
