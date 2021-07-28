package io.jsonwebtoken.impl.security

import io.jsonwebtoken.MalformedJwtException
import io.jsonwebtoken.impl.DefaultJweHeader
import io.jsonwebtoken.io.Encoders
import io.jsonwebtoken.lang.Arrays

import javax.crypto.SecretKey
import java.nio.charset.StandardCharsets

import static org.junit.Assert.*

import io.jsonwebtoken.security.EncryptionAlgorithms
import org.junit.Test

import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec

class AesGcmKeyAlgorithmTest {

    /**
     * This tests asserts that our EncyrptionAlgorithm implementation and the JCA 'AES/GCM/NoPadding' wrap algorithm
     * produce the exact same values.  This should be the case when the transformation is identical, even though
     * one uses Cipher.WRAP_MODE and the other uses a raw plaintext byte array.
     */
    @Test
    void testAesWrapProducesSameResultAsAesAeadEncryptionAlgorithm() {

        def alg = new GcmAesAeadAlgorithm(256)

        def iv = new byte[12];
        Randoms.secureRandom().nextBytes(iv);

        def kek = alg.generateKey();
        def cek = alg.generateKey();

        JcaTemplate template = new JcaTemplate("AES/GCM/NoPadding", null)
        byte[] jcaResult = template.execute(Cipher.class, new InstanceCallback<Cipher, byte[]>() {
            @Override
            byte[] doWithInstance(Cipher cipher) throws Exception {
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

        def encRequest = new DefaultSymmetricAeadRequest(null, null, cek.getEncoded(), kek, null, iv)
        def encResult = EncryptionAlgorithms.A256GCM.encrypt(encRequest)

        assertArrayEquals resultA.authenticationTag, encResult.authenticationTag
        assertArrayEquals resultA.initializationVector, encResult.initializationVector
        assertArrayEquals resultA.payload, encResult.payload
    }

    static void assertAlgorithm(int keyLength) {

        def alg = new AesGcmKeyAlgorithm(keyLength)
        assertEquals 'A' + keyLength + 'GCMKW', alg.getId()

        def template = new JcaTemplate('AES', null)

        def header = new DefaultJweHeader()
        def kek = template.generateSecretKey(keyLength)
        def cek = template.generateSecretKey(keyLength)

        def ereq = new DefaultKeyRequest(null, null, cek, kek, header)

        def result = alg.getEncryptionKey(ereq)
        header.putAll(result.getHeaderParams())

        byte[] encryptedKeyBytes = result.getPayload()
        assertFalse "encryptedKey must be populated", Arrays.length(encryptedKeyBytes) == 0

        def dcek = alg.getDecryptionKey(new DefaultKeyRequest<byte[], SecretKey>(null, null, encryptedKeyBytes, kek, header))

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
        def ereq = new DefaultKeyRequest(null, null, cek, kek, header)
        def result = alg.getEncryptionKey(ereq)
        header.putAll(result.getHeaderParams())

        header.put(headerName, value) //null value will remove it

        byte[] encryptedKeyBytes = result.getPayload()

        try {
            alg.getDecryptionKey(new DefaultKeyRequest<byte[], SecretKey>(null, null, encryptedKeyBytes, kek, header))
            fail()
        } catch (MalformedJwtException iae) {
            assertEquals exmsg, iae.getMessage()
        }
    }

    String missing(String name) {
        return "The A128GCMKW Key Management Algorithm requires a JweHeader '${name}' value." as String
    }

    String type(String name) {
        return "The A128GCMKW Key Management Algorithm requires the JweHeader '${name}' value to be a Base64URL-encoded String. Actual type: java.lang.Integer" as String
    }
    String base64Url(String name) {
        return "JweHeader '${name}' value 'T#ZW@#' does not appear to be a valid Base64URL String: Illegal base64url character: '#'"
    }
    String length(String name, int requiredLen) {
        return "The 'A128GCMKW' key management algorithm requires the JweHeader '${name}' value to be ${requiredLen * Byte.SIZE} bits (${requiredLen} bytes) in length. Actual length: 16 bits (2 bytes)."
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
        testDecryptionHeader('iv', value, length('iv', 12))
        testDecryptionHeader('tag', value, length('tag', 16))
    }
}
