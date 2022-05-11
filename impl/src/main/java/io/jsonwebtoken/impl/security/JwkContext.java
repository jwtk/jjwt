package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.Identifiable;

import java.net.URI;
import java.security.Key;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Map;
import java.util.Set;

public interface JwkContext<K extends Key> extends Identifiable, Map<String,Object> {

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

    Provider getProvider();

    JwkContext<K> setProvider(Provider provider);

    SecureRandom getRandom();

    JwkContext<K> setRandom(SecureRandom random);
}
