package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.impl.JwtMap;
import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.lang.Strings;
import io.jsonwebtoken.security.Jwk;

import java.security.Key;
import java.util.Map;
import java.util.Set;

class DefaultJwk<K extends Key> extends JwtMap implements Jwk<Object, K> {

    static final String TYPE = "kty";
    static final String USE = "use";
    static final String OPERATIONS = "key_ops";
    static final String ALGORITHM = "alg";
    static final String ID = "kid";
    static final String X509_URL = "x5u";
    static final String X509_CERT_CHAIN = "x5c";
    static final String X509_SHA1_THUMBPRINT = "x5t";
    static final String X509_SHA256_THUMBPRINT = "x5t#S256";

    private final String type;
    private final Set<String> operations;
    private final String algorithm;
    private final String id;

    private final K key;

    DefaultJwk(String type, Set<String> operations, String algorithm, String id, K key, Map<String, ?> values) {
        super(values);
        this.type = Assert.notNull(Strings.clean(type), "JWK type cannot be null or empty.");
        this.operations = operations;
        this.algorithm = algorithm;
        this.id = id;
        this.key = Assert.notNull(key, "Key argument cannot be null.");
    }

    @Override
    public String getType() {
        return this.type;
    }

    @Override
    public Set<String> getOperations() {
        return this.operations;
    }

    @Override
    public String getAlgorithm() {
        return this.algorithm;
    }

    @Override
    public String getId() {
        return this.id;
    }

    @Override
    public K toKey() {
        return this.key;
    }
}
