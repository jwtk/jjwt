/*
 * Copyright (C) 2018 jsonwebtoken.io
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
package io.jsonwebtoken.security

import io.jsonwebtoken.Jwts
import io.jsonwebtoken.impl.io.Streams
import io.jsonwebtoken.impl.security.DefaultAeadRequest
import io.jsonwebtoken.impl.security.DefaultAeadResult
import io.jsonwebtoken.impl.security.DefaultDecryptAeadRequest
import io.jsonwebtoken.impl.security.GcmAesAeadAlgorithm
import io.jsonwebtoken.lang.Registry
import org.junit.Test

import static org.junit.Assert.*

/**
 * Tests the {@link Jwts.ENC} implementation.
 *
 * @since 0.12.0
 */
class EncryptionAlgorithmsTest {

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

    private static final byte[] PLAINTEXT_BYTES = PLAINTEXT.getBytes("UTF-8")

    private static final String AAD = 'You can get with this, or you can get with that'
    private static final byte[] AAD_BYTES = AAD.getBytes("UTF-8")

    private static final Registry<String, AeadAlgorithm> registry = Jwts.ENC.get()

    static boolean contains(AeadAlgorithm alg) {
        return registry.containsValue(alg)
    }

    @Test
    void testValues() {
        assertEquals 6, registry.values().size()
        assertTrue(contains(Jwts.ENC.A128CBC_HS256) &&
                contains(Jwts.ENC.A192CBC_HS384) &&
                contains(Jwts.ENC.A256CBC_HS512) &&
                contains(Jwts.ENC.A128GCM) &&
                contains(Jwts.ENC.A192GCM) &&
                contains(Jwts.ENC.A256GCM)
        )
    }

    @Test
    void testForKey() {
        for (AeadAlgorithm alg : registry.values()) {
            assertSame alg, registry.forKey(alg.getId())
        }
    }

    @Test(expected = IllegalArgumentException)
    void testForIdWithInvalidId() {
        //unlike the 'get' paradigm, 'key' requires the value to exist
        registry.forKey('invalid')
    }

    @Test
    void testGet() {
        for (AeadAlgorithm alg : registry.values()) {
            assertSame alg, registry.get(alg.getId())
        }
    }

    @Test
    void testGetWithInvalidId() {
        // 'get' paradigm can return null if not found
        assertNull registry.get('invalid')
    }

    @Test
    void testWithoutAad() {

        for (AeadAlgorithm alg : registry.values()) {

            def key = alg.key().build()

            def out = new ByteArrayOutputStream()
            def request = new DefaultAeadRequest(Streams.of(PLAINTEXT_BYTES), null, null, key, null)
            def result = new DefaultAeadResult(out)

            alg.encrypt(request, result)
            byte[] iv = result.getIv()
            byte[] tag = result.getDigest() //there is always a tag, even if there is no AAD
            assertNotNull tag

            byte[] ciphertextBytes = out.toByteArray()

            //AES GCM always results in ciphertext the same length as the plaintext:
            if (alg instanceof GcmAesAeadAlgorithm) {
                assertEquals(ciphertextBytes.length, PLAINTEXT_BYTES.length)
            }

            def ciphertext = Streams.of(ciphertextBytes)
            out = new ByteArrayOutputStream(8192)
            def dreq = new DefaultDecryptAeadRequest(ciphertext, key, null, iv, tag)
            alg.decrypt(dreq, out)
            byte[] decryptedPlaintextBytes = out.toByteArray()

            assertArrayEquals(PLAINTEXT_BYTES, decryptedPlaintextBytes)
        }
    }

    @Test
    void testWithAad() {

        for (AeadAlgorithm alg : registry.values()) {

            def key = alg.key().build()

            def plaintextIn = Streams.of(PLAINTEXT_BYTES)
            def out = new ByteArrayOutputStream(8192)
            def aad = Streams.of(AAD_BYTES)
            def req = new DefaultAeadRequest(plaintextIn, null, null, key, aad)
            def res = new DefaultAeadResult(out)

            alg.encrypt(req, res)
            byte[] iv = res.getIv()
            byte[] tag = res.getDigest()
            byte[] ciphertextBytes = out.toByteArray()
            Streams.reset(aad)

            //AES GCM always results in ciphertext the same length as the plaintext:
            if (alg instanceof GcmAesAeadAlgorithm) {
                assertEquals(ciphertextBytes.length, PLAINTEXT_BYTES.length)
            }

            def ciphertext = Streams.of(ciphertextBytes)
            out = new ByteArrayOutputStream(8192)
            def dreq = new DefaultDecryptAeadRequest(ciphertext, key, aad, iv, tag)
            alg.decrypt(dreq, out)
            byte[] decryptedPlaintextBytes = out.toByteArray()
            assertArrayEquals(PLAINTEXT_BYTES, decryptedPlaintextBytes)
        }
    }
}
