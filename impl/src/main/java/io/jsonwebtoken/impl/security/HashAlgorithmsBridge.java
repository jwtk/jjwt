package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.impl.lang.IdRegistry;
import io.jsonwebtoken.lang.Collections;
import io.jsonwebtoken.security.DigestAlgorithm;
import io.jsonwebtoken.security.HashAlgorithm;

/**
 * Static class definitions for standard {@link DigestAlgorithm} instances.
 *
 * @since JJWT_RELEASE_VERSION
 */
@SuppressWarnings("unused") // used via reflection in io.jsonwebtoken.security.Algorithms.StandardHashAlgorithms
public class HashAlgorithmsBridge extends DelegatingRegistry<HashAlgorithm> {
    public HashAlgorithmsBridge() {
        super(new IdRegistry<>("IANA Hash Algorithm", Collections.of(
                DefaultHashAlgorithm.SHA256
        )));
    }
}
