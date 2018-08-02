package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.impl.JwtMap;
import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.lang.Collections;
import io.jsonwebtoken.lang.Strings;
import io.jsonwebtoken.security.Jwk;
import io.jsonwebtoken.security.MalformedKeyException;

import java.lang.reflect.Array;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

@SuppressWarnings("unchecked")
abstract class AbstractJwk<T extends Jwk> extends JwtMap implements Jwk<T> {

    static final String TYPE = "kty";
    static final String USE = "use";
    static final String OPERATIONS = "key_ops";
    static final String ALGORITHM = "alg";
    static final String ID = "kid";
    static final String X509_URL = "x5u";
    static final String X509_CERT_CHAIN = "x5c";
    static final String X509_SHA1_THUMBPRINT = "x5t";
    static final String X509_SHA256_THUMBPRINT = "x5t#S256";

    AbstractJwk(String type) {
        type = Strings.clean(type);
        Assert.notNull(type, "JWK type cannot be null or empty.");
        put(TYPE, type);
    }

    T setRequiredValue(String key, Object value, String name) {
        boolean reduceable = value != null && isReduceableToNull(value);
        if (reduceable) {
            value = null;
        }
        if (value == null) {
            String msg = getType() + " JWK " + name + " ('" + key + "' property) cannot be null";
            if (reduceable) {
                msg += " or empty";
            }
            msg += ".";
            throw new IllegalArgumentException(msg);
        }
        setValue(key, value);
        return (T) this;
    }

    protected List<String> getList(String name) {
        Object value = get(name);
        if (value == null) {
            return null;
        }
        List<String> list = new ArrayList<>();
        if (value instanceof Collection) {
            Collection c = (Collection)value;
            for (Object o : c) {
                list.add(o == null ? null : String.valueOf(o));
            }
        } else if (value.getClass().isArray()) {
            int length = Array.getLength(value);
            for (int i = 0; i < length; i ++) {
                Object o = Array.get(value, i);
                list.add(o == null ? null : String.valueOf(o));
            }
        }
        return list;
    }

    @Override
    public String getType() {
        return getString(TYPE);
    }

    @Override
    public String getUse() {
        return getString(USE);
    }

    @Override
    public T setUse(String use) {
        setValue(USE, Strings.clean(use));
        return (T)this;
    }

    @Override
    public Set<String> getOperations() {
        Object val = get(OPERATIONS);
        if (val instanceof Set) {
            return (Set)val;
        }
        List<String> list = getList(OPERATIONS);
        return val == null ? null : new LinkedHashSet<>(list);
    }

    @Override
    public T setOperations(Set<String> ops) {
        Set<String> operations = Collections.isEmpty(ops) ? null : new LinkedHashSet<>(ops);
        setValue(OPERATIONS, operations);
        return (T)this;
    }

    @Override
    public String getAlgorithm() {
        return getString(ALGORITHM);
    }

    @Override
    public T setAlgorithm(String alg) {
        setValue(ALGORITHM, Strings.clean(alg));
        return (T)this;
    }

    @Override
    public String getId() {
        return getString(ID);
    }

    @Override
    public T setId(String id) {
        setValue(ID, Strings.clean(id));
        return (T)this;
    }

    @Override
    public URI getX509Url() {
        Object val = get(X509_URL);
        if (val == null) {
            return null;
        }
        if (val instanceof URI) {
            return (URI)val;
        }
        String sval = String.valueOf(val);
        URI uri;
        try {
            uri = new URI(sval);
            setValue(X509_URL, uri); //replace with constructed instance
        } catch (URISyntaxException e) {
            String msg = getType() + " JWK x5u value cannot be converted to a URI instance: " + sval;
            throw new MalformedKeyException(msg, e);
        }
        return uri;
    }

    @Override
    public T setX509Url(URI url) {
        setValue(X509_URL, url);
        return (T)this;
    }

    @Override
    public List<String> getX509CertficateChain() {
        return getList(X509_CERT_CHAIN);
    }

    @Override
    public T setX509CertificateChain(List<String> chain) {
        chain = Collections.isEmpty(chain) ? null : new ArrayList<>(new LinkedHashSet<>(chain)); //guarantee no duplicate elements
        setValue(X509_CERT_CHAIN, chain);
        return (T)this;
    }

    @Override
    public String getX509CertificateSha1Thumbprint() {
        return getString(X509_SHA1_THUMBPRINT);
    }

    @Override
    public T setX509CertificateSha1Thumbprint(String thumbprint) {
        setValue(X509_SHA1_THUMBPRINT, Strings.clean(thumbprint));
        return (T)this;
    }

    @Override
    public String getX509CertificateSha256Thumbprint() {
        return getString(X509_SHA256_THUMBPRINT);
    }

    @Override
    public T setX509CertificateSha256Thumbprint(String thumbprint) {
        setValue(X509_SHA256_THUMBPRINT, Strings.clean(thumbprint));
        return (T)this;
    }
}
