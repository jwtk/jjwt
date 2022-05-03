package io.jsonwebtoken.impl.security

import io.jsonwebtoken.MalformedJwtException
import io.jsonwebtoken.impl.DefaultJweHeader
import io.jsonwebtoken.impl.lang.Bytes
import io.jsonwebtoken.impl.lang.CheckedFunction
import io.jsonwebtoken.impl.lang.CheckedSupplier
import io.jsonwebtoken.impl.lang.Conditions
import io.jsonwebtoken.io.Encoders
import io.jsonwebtoken.lang.Arrays
import io.jsonwebtoken.security.EncryptionAlgorithms
import io.jsonwebtoken.security.SecretKeyBuilder
import org.junit.Test

import javax.crypto.Cipher
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import java.nio.charset.StandardCharsets
import java.security.Provider

import static org.junit.Assert.*

class AesGcmKeyAlgorithmTest {

    /**
     * This tests asserts that our AeadAlgorithm implementation and the JCA 'AES/GCM/NoPadding' wrap algorithm
     * produce the exact same values.  This should be the case when the transformation is identical, even though
     * one uses Cipher.WRAP_MODE and the other uses a raw plaintext byte array.
     */
    @Test
    void testAesWrapProducesSameResultAsAesAeadEncryptionAlgorithm() {

        def alg = new GcmAesAeadAlgorithm(256)

        def iv = new byte[12];
        Randoms.secureRandom().nextBytes(iv);

        def kek = alg.keyBuilder().build()
        def cek = alg.keyBuilder().build()

        final String jcaName = "AES/GCM/NoPadding"

        // AES/GCM/NoPadding is only available on JDK 8 and later, so enable BC as a backup provider if
        // necessary for <= JDK 7:
        // TODO: remove when dropping Java 7 support:
        Provider provider = Providers.findBouncyCastle(Conditions.notExists(new CheckedSupplier<SecretKeyFactory>() {
            @Override
            SecretKeyFactory get() throws Exception {
                return SecretKeyFactory.getInstance(jcaName);
            }
        }))

        JcaTemplate template = new JcaTemplate(jcaName, provider)
        byte[] jcaResult = template.execute(Cipher.class, new CheckedFunction<Cipher, byte[]>() {
            @Override
            byte[] apply(Cipher cipher) throws Exception {
                cipher.init(Cipher.WRAP_MODE, kek, new GCMParameterSpec(128, iv))
                return cipher.wrap(cek)
            }
        })

        //separate tag from jca ciphertext:
        int ciphertextLength = jcaResult.length - 16; //AES block size in bytes (128 bits)
        byte[] ciphertext = new byte[ciphertextLength]
        System.arraycopy(jcaResult, 0, ciphertext, 0, ciphertextLength)

        byte[] tag = new byte[16]
        System.arraycopy(jcaResult, ciphertextLength, tag, 0, 16)
        def resultA = new DefaultAeadResult(null, null, ciphertext, kek, null, tag, iv)

        def encRequest = new DefaultAeadRequest(null, null, cek.getEncoded(), kek, null, iv)
        def encResult = EncryptionAlgorithms.A256GCM.encrypt(encRequest)

        assertArrayEquals resultA.digest, encResult.digest
        assertArrayEquals resultA.initializationVector, encResult.initializationVector
        assertArrayEquals resultA.getContent(), encResult.getContent()
    }

    static void assertAlgorithm(int keyLength) {

        def alg = new AesGcmKeyAlgorithm(keyLength)
        assertEquals 'A' + keyLength + 'GCMKW', alg.getId()

        def template = new JcaTemplate('AES', null)

        def header = new DefaultJweHeader()
        def kek = template.generateSecretKey(keyLength)
        def cek = template.generateSecretKey(keyLength)
        def enc = new GcmAesAeadAlgorithm(keyLength) {
            @Override
            SecretKeyBuilder keyBuilder() {
                return new FixedSecretKeyBuilder(cek)
            }
        }

        def ereq = new DefaultKeyRequest(null, null, kek, header, enc)

        def result = alg.getEncryptionKey(ereq)

        byte[] encryptedKeyBytes = result.getContent()
        assertFalse "encryptedKey must be populated", Arrays.length(encryptedKeyBytes) == 0

        def dcek = alg.getDecryptionKey(new DefaultDecryptionKeyRequest(null, null, kek, header, enc, encryptedKeyBytes))

        //Assert the decrypted key matches the original cek
        assertEquals cek.algorithm, dcek.algorithm
        assertArrayEquals cek.encoded, dcek.encoded
    }

    @Test
    void testResultSymmetry() {
        assertAlgorithm(128)
        assertAlgorithm(192)
        assertAlgorithm(256)
    }

    static void testDecryptionHeader(String headerName, Object value, String exmsg) {
        int keyLength = 128
        def alg = new AesGcmKeyAlgorithm(keyLength)
        def template = new JcaTemplate('AES', null)
        def header = new DefaultJweHeader()
        def kek = template.generateSecretKey(keyLength)
        def cek = template.generateSecretKey(keyLength)
        def enc = new GcmAesAeadAlgorithm(keyLength) {
            @Override
            SecretKeyBuilder keyBuilder() {
                return new FixedSecretKeyBuilder(cek)
            }
        }
        def ereq = new DefaultKeyRequest(null, null, kek, header, enc)
        def result = alg.getEncryptionKey(ereq)

        header.put(headerName, value) //null value will remove it

        byte[] encryptedKeyBytes = result.getContent()

        try {
            alg.getDecryptionKey(new DefaultDecryptionKeyRequest(null, null, kek, header, enc, encryptedKeyBytes))
            fail()
        } catch (MalformedJwtException iae) {
            assertEquals exmsg, iae.getMessage()
        }
    }

    String missing(String name) {
        return "JWE header is missing required '${name}' value." as String
    }

    String type(String name) {
        return "JWE header '${name}' value must be a String. Actual type: java.lang.Integer" as String
    }

    String base64Url(String name) {
        return "JWE header '${name}' value is not a valid Base64URL String: Illegal base64url character: '#'"
    }

    String length(String name, int requiredBitLength) {
        return "JWE header '${name}' decoded byte array must be ${Bytes.bitsMsg(requiredBitLength)} long. Actual length: ${Bytes.bitsMsg(16)}."
    }

    @Test
    void testMissingHeaders() {
        testDecryptionHeader('iv', null, missing('iv'))
        testDecryptionHeader('tag', null, missing('tag'))
    }

    @Test
    void testIncorrectTypeHeaders() {
        testDecryptionHeader('iv', 14, type('iv'))
        testDecryptionHeader('tag', 14, type('tag'))
    }

    @Test
    void testInvalidBase64UrlHeaders() {
        testDecryptionHeader('iv', 'T#ZW@#', base64Url('iv'))
        testDecryptionHeader('tag', 'T#ZW@#', base64Url('tag'))
    }

    @Test
    void testIncorrectLengths() {
        def value = Encoders.BASE64URL.encode("hi".getBytes(StandardCharsets.US_ASCII))
        testDecryptionHeader('iv', value, length('iv', 96))
        testDecryptionHeader('tag', value, length('tag', 128))
    }
}
