package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.security.Identifiable;

import java.net.URI;
import java.security.Key;
import java.security.Provider;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Set;

public interface JwkContext<K extends Key> extends Identifiable {

    int size();

    boolean isEmpty();

    boolean containsKey(String key);

    boolean containsValue(Object value);

    Object get(String key);

    Set<String> keySet();

    Collection<Object> values();

    Set<Map.Entry<String, Object>> entrySet();

    Map<String,Object> getValues();

    Object put(String name, Object value);

    void putAll(Map<? extends String, ?> m);

    void setId(String id);

    String getType();

    void setType(String type);

    Set<String> getOperations();

    void setOperations(Set<String> operations);

    String getAlgorithm();

    void setAlgorithm(String algorithm);

    String getPublicKeyUse();

    void setPublicKeyUse(String use);

    URI getX509Url();

    void setX509Url(URI url);

    List<X509Certificate> getX509CertificateChain();

    void setX509CertificateChain(List<X509Certificate> x5c);

    byte[] getX509CertificateSha1Thumbprint();

    void setX509CertificateSha1Thumbprint(byte[] x5t);

    byte[] getX509CertificateSha256Thumbprint();

    void setX509CertificateSha256Thumbprint(byte[] x5ts256);

    K getKey();

    JwkContext<K> setKey(K key);

    PublicKey getPublicKey();

    void setPublicKey(PublicKey publicKey);

    Set<String> getPrivateMemberNames();

    Provider getProvider();

    void setProvider(Provider provider);
}
