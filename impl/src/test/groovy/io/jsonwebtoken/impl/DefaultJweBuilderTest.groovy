package io.jsonwebtoken.impl

import io.jsonwebtoken.Jwts
import io.jsonwebtoken.security.EncryptionAlgorithms
import org.junit.Test

import static org.junit.Assert.assertEquals
import static org.junit.Assert.fail

class DefaultJweBuilderTest {

    static DefaultJweBuilder builder() {
        return new DefaultJweBuilder()
    }

    @Test
    void testCompactWithoutPayloadOrClaims() {
        try {
            builder().compact()
            fail()
        } catch (IllegalStateException ise) {
            assertEquals "Either 'claims' or a non-empty 'payload' must be specified.", ise.message
        }
    }

    @Test
    void testCompactWithoutBothPayloadAndClaims() {
        try {
            builder().setPayload("hi").setIssuer("me").compact()
        } catch (IllegalStateException ise) {
            assertEquals "Both 'payload' and 'claims' cannot both be specified. Choose either one.", ise.message
        }
    }

    @Test
    void testCompactWithoutKey() {
        try {
            builder().setIssuer("me").compact()
        } catch (IllegalStateException ise) {
            assertEquals 'Key is required.', ise.message
        }
    }

    @Test
    void testCompactWithoutEncryptionAlgorithm() {
        def key = EncryptionAlgorithms.A128GCM.generateKey()
        try {
            builder().setIssuer("me").withKey(key).compact()
        } catch (IllegalStateException ise) {
            assertEquals 'Encryption algorithm is required.', ise.message
        }
    }

    @Test
    void testCompactSimplestPayload() {
        def enc = EncryptionAlgorithms.A128GCM
        def key = enc.generateKey()
        def jwe = builder().setPayload("me").encryptWith(enc).withKey(key).compact()
        def jwt = Jwts.parserBuilder().decryptWith(key).build().parsePlaintextJwe(jwe)
        assertEquals 'me', jwt.getBody()
    }

    @Test
    void testCompactSimplestClaims() {
        def enc = EncryptionAlgorithms.A128GCM
        def key = enc.generateKey()
        def jwe = builder().setSubject('joe').encryptWith(enc).withKey(key).compact()
        def jwt = Jwts.parserBuilder().decryptWith(key).build().parseClaimsJwe(jwe)
        assertEquals 'joe', jwt.getBody().getSubject()
    }

    /*
    @Test
    void testFullSymmetryForAllJweAlgorithms() {

        for( KeyAlgorithm<? extends Key,? extends Key> keyAlg : KeyAlgorithms.values() ) {

            for(AeadAlgorithm encAlg : EncryptionAlgorithms.values() ) {
                Key kek = encAlg.generateKey();
                String jwe = builder().setSubject('joe').encryptWith(encAlg).withKeyFrom(kek, keyAlg).compact()
            }
        }
    }
     */

    @Test
    void testBuild() {
        def enc = EncryptionAlgorithms.A128GCM;
        def key = enc.generateKey()

        String jwe = new DefaultJweBuilder()
                .setSubject('joe')
                .encryptWith(enc)
                .withKey(key)
                .compact()

        //TODO create assertions
        //println jwe
        //println new String(Decoders.BASE64URL.decode(jwe.substring(0, jwe.indexOf('.'))), StandardCharsets.UTF_8)
    }
}
