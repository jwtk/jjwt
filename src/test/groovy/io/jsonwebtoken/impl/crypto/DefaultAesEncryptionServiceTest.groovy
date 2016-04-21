/*
 * Copyright (C) 2016 jsonwebtoken.io
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.jsonwebtoken.impl.crypto

import groovy.json.internal.Charsets
import org.junit.Test

import javax.crypto.*
import java.security.InvalidAlgorithmParameterException
import java.security.InvalidKeyException
import java.security.NoSuchAlgorithmException
import java.security.SecureRandom

import static org.junit.Assert.*

class DefaultAesEncryptionServiceTest {

    private static final String PLAINTEXT =
            '''Bacon ipsum dolor amet venison beef pork chop, doner jowl pastrami ground round alcatra.
               Beef leberkas filet mignon ball tip pork spare ribs kevin short loin ribeye ground round
               biltong jerky short ribs corned beef. Strip steak turducken meatball porchetta beef ribs
               shoulder pork belly doner salami corned beef kielbasa cow filet mignon drumstick. Bacon
               tenderloin pancetta flank frankfurter ham kevin leberkas meatball turducken beef ribs.
               Cupim short loin short ribs shankle tenderloin. Ham ribeye hamburger flank tenderloin
               cupim t-bone, shank tri-tip venison salami sausage pancetta. Pork belly chuck salami
               alcatra sirloin.

               以ケ ホゥ婧詃 橎ちゅぬ蛣埣 禧ざしゃ蟨廩 椥䤥グ曣わ 基覧 滯っ䶧きょメ Ủ䧞以ケ妣 择禤槜谣お 姨のドゥ,
               らボみょば䪩 苯礊觊ツュ婃 䩦ディふげセ げセりょ 禤槜 Ủ䧞以ケ妣 せがみゅちょ䰯 择禤槜谣お 難ゞ滧 蝥ちゃ,
               滯っ䶧きょメ らボみょば䪩 礯みゃ楦と饥 椥䤥グ ウァ槚 訤をりゃしゑ びゃ驨も氩簥 栨キョ奎婨榞 ヌに楃 以ケ,
               姚奊べ 椥䤥グ曣わ 栨キョ奎婨榞 ちょ䰯 Ủ䧞以ケ妣 誧姨のドゥろ よ苯礊 く涥, りゅぽ槞 馣ぢゃ尦䦎ぎ
               大た䏩䰥ぐ 郎きや楺橯 䧎キェ, 難ゞ滧 栧择 谯䧟簨訧ぎょ 椥䤥グ曣わ'''

    private static final byte[] PLAINTEXT_BYTES = PLAINTEXT.getBytes(Charsets.UTF_8)

    private static final String AAD = 'You can get with this, or you can get with that'
    private static final byte[] AAD_BYTES = AAD.getBytes(Charsets.UTF_8)

    private byte[] generateKey() {
        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(256);
        return kg.generateKey().getEncoded();
    }

    @Test
    void testSimple() {

        byte[] key = generateKey();

        def service = new DefaultAesEncryptionService(key);

        def ciphertext = service.encrypt(PLAINTEXT_BYTES);

        def decryptedPlaintextBytes = service.decrypt(ciphertext);

        def decryptedPlaintext = new String(decryptedPlaintextBytes, Charsets.UTF_8);

        assertEquals(PLAINTEXT, decryptedPlaintext);
    }

    @Test
    void testDoEncryptFailure() {
        String msg = 'foo'
        def key = generateKey()
        def service = new DefaultAesEncryptionService(key) {
            @Override
            protected EncryptionResult doEncrypt(EncryptionRequest req) throws InvalidAlgorithmParameterException, InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException, ShortBufferException, BadPaddingException, IllegalBlockSizeException {
                throw new IllegalArgumentException(msg)
            }
        }

        try {
            service.encrypt(key /*any byte array will do */)
            fail("Encryption should have failed")
        } catch (CryptoException expected) {
            assertEquals('Unable to perform encryption: ' + msg, expected.message)
        }
    }

    @Test
    void testDoDecryptFailure() {
        String msg = 'foo'
        def key = generateKey()
        def service = new DefaultAesEncryptionService(key) {
            @Override
            protected byte[] doDecrypt(DecryptionRequest req) throws InvalidAlgorithmParameterException, InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException, ShortBufferException, BadPaddingException, IllegalBlockSizeException {
                throw new IllegalArgumentException(msg)
            }
        }
        try {
            service.decrypt(key /*any byte array will do */)
            fail("Decryption should have failed")
        } catch (CryptoException expected) {
            assertEquals('Unable to perform decryption: ' + msg, expected.message)
        }
    }

    @Test
    void testEncryptWithSpecifiedKey() {

        def service = new DefaultAesEncryptionService(generateKey());

        //use a custom key for this request:
        def key = generateKey()

        EncryptionRequest ereq = EncryptionRequests.builder().setKey(key).setPlaintext(PLAINTEXT_BYTES).build()

        EncryptionResult eres = service.encrypt(ereq);

        DecryptionRequest dreq = DecryptionRequests.builder().setKey(key)
                .setInitializationVector(eres.getInitializationVector())
                .setCiphertext(eres.getCiphertext())
                .build()

        def decryptedPlaintextBytes = service.decrypt(dreq)

        def decryptedPlaintext = new String(decryptedPlaintextBytes, Charsets.UTF_8);

        assertEquals(PLAINTEXT, decryptedPlaintext);
    }

    @Test
    void testEncryptWithSpecifiedIv() {

        def service = new DefaultAesEncryptionService(generateKey());

        byte[] iv = new byte[12]; //AES GCM tends to use nonces of 12 bytes for efficiency
        new SecureRandom().nextBytes(iv);

        EncryptionRequest ereq = EncryptionRequests.builder()
                .setInitializationVector(iv)
                .setPlaintext(PLAINTEXT_BYTES)
                .build()

        EncryptionResult eres = service.encrypt(ereq);

        DecryptionRequest dreq = DecryptionRequests.builder()
                .setInitializationVector(iv)
                .setCiphertext(eres.getCiphertext())
                .build()

        def decryptedPlaintextBytes = service.decrypt(dreq)

        def decryptedPlaintext = new String(decryptedPlaintextBytes, Charsets.UTF_8);

        assertEquals(PLAINTEXT, decryptedPlaintext);
    }

    @Test
    void testDecryptWithEmptyIv() {

        def service = new DefaultAesEncryptionService(generateKey());

        DecryptionRequest dreq = DecryptionRequests.builder().setCiphertext(generateKey()).build()

        try {
            service.decrypt(dreq)
            fail()
        } catch (CryptoException expected) {
            assertTrue expected.getMessage().endsWith(DefaultAesEncryptionService.DECRYPT_NO_IV);
        }

    }

    @Test
    void testEncryptAdditionalAuthenticatedData() {

        def service = new DefaultAesEncryptionService(generateKey());

        EncryptionRequest ereq = EncryptionRequests.builder()
                .setPlaintext(PLAINTEXT_BYTES)
                .setAdditionalAuthenticatedData(AAD_BYTES)
                .build()

        AuthenticatedEncryptionResult eres = (AuthenticatedEncryptionResult) service.encrypt(ereq);

        DecryptionRequest dreq = DecryptionRequests.builder()
                .setInitializationVector(eres.getInitializationVector())
                .setCiphertext(eres.getCiphertext())
                .setAdditionalAuthenticatedData(AAD_BYTES)
                .setAuthenticationTag(eres.getAuthenticationTag())
                .build()

        def decryptedPlaintextBytes = service.decrypt(dreq)

        def decryptedPlaintext = new String(decryptedPlaintextBytes, Charsets.UTF_8);

        assertEquals(PLAINTEXT, decryptedPlaintext);
    }

    @Test
    void testEncryptWithEmptyAdditionalAuthenticatedData() {

        def service = new DefaultAesEncryptionService(generateKey());

        def ereq = new DummyEncryptionRequest(plaintext: PLAINTEXT_BYTES)

        def eres = service.encrypt(ereq)

        assertTrue eres instanceof DefaultEncryptionResult
        assertFalse eres instanceof AuthenticatedEncryptionResult

        DecryptionRequest dreq = DecryptionRequests.builder()
                .setInitializationVector(eres.getInitializationVector())
                .setCiphertext(eres.getCiphertext())
                .build()

        def decryptedPlaintextBytes = service.decrypt(dreq)

        def decryptedPlaintext = new String(decryptedPlaintextBytes, Charsets.UTF_8);

        assertEquals(PLAINTEXT, decryptedPlaintext);
    }

    @Test
    void testDecryptWithSpecifiedKey() {

        def key = generateKey()

        def service = new DefaultAesEncryptionService(key);

        EncryptionRequest ereq = EncryptionRequests.builder()
                .setPlaintext(PLAINTEXT_BYTES)
                .build()

        def eres = service.encrypt(ereq)

        assertTrue eres instanceof DefaultEncryptionResult
        assertFalse eres instanceof AuthenticatedEncryptionResult

        DecryptionRequest dreq = DecryptionRequests.builder()
                .setKey(key)
                .setInitializationVector(eres.getInitializationVector())
                .setCiphertext(eres.getCiphertext())
                .build()

        def decryptedPlaintextBytes = service.decrypt(dreq)

        def decryptedPlaintext = new String(decryptedPlaintextBytes, Charsets.UTF_8);

        assertEquals(PLAINTEXT, decryptedPlaintext);
    }

    private static class DummyEncryptionRequest implements EncryptionRequest, AssociatedDataSource {

        byte[] plaintext;

        @Override
        SecureRandom getSecureRandom() {
            return null;
        }

        @Override
        byte[] getAssociatedData() {
            return new byte[0]
        }

        @Override
        byte[] getPlaintext() {
            return this.plaintext
        }

        @Override
        byte[] getKey() {
            return null
        }

        @Override
        byte[] getInitializationVector() {
            return null
        }
    }
}
