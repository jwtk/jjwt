package io.jsonwebtoken.security;

import javax.crypto.SecretKey;
import java.security.Key;
import java.security.KeyPair;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

public interface ProtoJwkBuilder<K extends Key, J extends Jwk<K>, T extends JwkBuilder<K, J, T>> extends JwkBuilder<K, J, T> {

    SecretJwkBuilder setKey(SecretKey key);

    RsaPublicJwkBuilder setKey(RSAPublicKey key);

    RsaPrivateJwkBuilder setKey(RSAPrivateKey key);

    EcPublicJwkBuilder setKey(ECPublicKey key);

    EcPrivateJwkBuilder setKey(ECPrivateKey key);

    RsaPrivateJwkBuilder setKeyPairRsa(KeyPair keyPair);

    EcPrivateJwkBuilder setKeyPairEc(KeyPair keyPair);
}
