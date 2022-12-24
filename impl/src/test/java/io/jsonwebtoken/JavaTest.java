package io.jsonwebtoken;

import io.jsonwebtoken.impl.security.TestKeys;
import io.jsonwebtoken.security.EncryptionAlgorithms;
import io.jsonwebtoken.security.KeyAlgorithms;
import io.jsonwebtoken.security.SignatureAlgorithms;
import org.junit.Ignore;
import org.junit.Test;

import javax.crypto.SecretKey;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

public class JavaTest {

    @Test
    @Ignore
    public void testFoo() {

        SecretKey secretKey = TestKeys.getA128CBC_HS256();
        PublicKey pubKey = TestKeys.getRS256().getPair().getPublic();
        RSAPublicKey rsaPub = (RSAPublicKey)pubKey;
        PrivateKey privKey = TestKeys.getRS256().getPair().getPrivate();
        RSAPrivateKey rsaPriv = (RSAPrivateKey)privKey;

        ECPublicKey ecPub = (ECPublicKey)TestKeys.getES256().getPair().getPublic();
        ECPrivateKey ecPriv = (ECPrivateKey)TestKeys.getES256().getPair().getPrivate();

        //Jwts.builder().encryptWith(EncryptionAlgorithms.A128GCM).using(pubKey).producedBy(KeyAlgorithms.RSA_OAEP);
        //Jwts.builder().encryptWith(EncryptionAlgorithms.A128GCM).using(pubKey).and(KeyAlgorithms.RSA_OAEP);

        Jwts.builder().signWith(ecPriv, SignatureAlgorithms.ES256).compact();

        // .setKeyLocator(keyLocator)
        // .locateKeysWith(keyLocator)


//        Jwts.builder().secureWith(secretKey).using(SignatureAlgorithms.HS256).compact();
//        Jwts.builder().secureWith(Keys.forPassword("foo".toCharArray())).and(KeyAlgorithms.PBES2_HS256_A128KW).compact();
//        Jwts.builder().secureWith(secretKey).using(EncryptionAlgorithms.A128GCM).compact();
//        Jwts.builder().secureWith(privKey).using(SignatureAlgorithms.RS256);
//        Jwts.builder().secureWith(pubKey).and(KeyAlgorithms.ECDH_ES).using(EncryptionAlgorithms.A128GCM);
//        Jwts.builder().secureWith(rsaPub).and(KeyAlgorithms.ECDH_ES).using(EncryptionAlgorithms.A256GCM);

        //Jwts.builder().encryptWith(pubKey).using(EncryptionAlgorithms.A128GCM).withKeyFrom(KeyAlgorithms.RSA_OAEP);
        //Jwts.builder().encryptWith(pubKey).and(KeyAlgorithms.RSA_OAEP).using(EncryptionAlgorithms.A128GCM);
        //Jwts.builder().encryptWith(rsaPub, KeyAlgorithms.RSA_OAEP).compact();

        //Jwts.builder().encryptWith(pubKey, KeyAlgorithms.RSA_OAEP).using(EncryptionAlgorithms.A128GCM);


        //Jwts.builder().using(SignatureAlgorithms.RS256);

        Jwts.builder().signWith(privKey, SignatureAlgorithms.RS256).compact();

        Jwts.builder().encryptWith(EncryptionAlgorithms.A256GCM, secretKey).compact();

        Jwts.builder().encryptWith(EncryptionAlgorithms.A256GCM, ecPub, KeyAlgorithms.ECDH_ES);

        //Jwts.builder().encryptWith(EncryptionAlgorithms.A256GCM, pubKey, KeyAlgorithms.ECDH_ES).compact();

        //Jwts.builder().signWith(ecPub).using(SignatureAlgorithms.RS256).compact();


        /*
        <K extends Key> JwtBuilder<K> encryptWith(AeadAlgorithm enc, K key, KeyAlgorithm<? super K, ?> keyAlg);

    <K extends Key> JwtBuilder<K> secureWith(K key);

    <T extends Key> JwtBuilder<T> secureWith(T key, KeyAlgorithm<T, ?> keyAlg);

    <K extends Key> JwtBuilder<K> protectWith(K key);

    JwtBuilder<K> withKeyFrom(KeyAlgorithm<K,?> alg);
    JwtBuilder<K> and(KeyAlgorithm<K,?> alg);

    JwtBuilder<K> using(AeadAlgorithm enc);

    JwtBuilder<K> using(io.jsonwebtoken.security.SignatureAlgorithm<? super K, ?> alg);
         */

    }
}
