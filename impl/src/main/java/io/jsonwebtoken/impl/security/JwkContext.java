package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.Identifiable;

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

    JwkContext<K> putAll(Map<? extends String, ?> m);

    JwkContext<K> setId(String id);

    String getType();

    JwkContext<K> setType(String type);

    Set<String> getOperations();

    JwkContext<K> setOperations(Set<String> operations);

    String getAlgorithm();

    JwkContext<K> setAlgorithm(String algorithm);

    String getPublicKeyUse();

    JwkContext<K> setPublicKeyUse(String use);

    URI getX509Url();

    JwkContext<K> setX509Url(URI url);

    List<X509Certificate> getX509CertificateChain();

    JwkContext<K> setX509CertificateChain(List<X509Certificate> x5c);

    byte[] getX509CertificateSha1Thumbprint();

    JwkContext<K> setX509CertificateSha1Thumbprint(byte[] x5t);

    byte[] getX509CertificateSha256Thumbprint();

    JwkContext<K> setX509CertificateSha256Thumbprint(byte[] x5ts256);

    K getKey();

    JwkContext<K> setKey(K key);

    PublicKey getPublicKey();

    JwkContext<K> setPublicKey(PublicKey publicKey);

    Set<String> getPrivateMemberNames();

    Provider getProvider();

    JwkContext<K> setProvider(Provider provider);
}
