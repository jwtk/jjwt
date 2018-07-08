package io.jsonwebtoken.codec.impl

import io.jsonwebtoken.lang.Strings
import org.junit.Test

import static org.junit.Assert.*

class Base64Test {

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

    @Test
    void testEncodeToStringWithNullArgument() {
        String s = Base64.DEFAULT.encodeToString(null, false)
        assertEquals 0, s.toCharArray().length
    }

    @Test
    void testEncodeToStringWithEmptyByteArray() {
        byte[] bytes = new byte[0]
        String s = Base64.DEFAULT.encodeToString(bytes, false)
        assertEquals 0, s.toCharArray().length
    }

    @Test
    void testLineSeparators() {
        byte[] bytes = PLAINTEXT.getBytes(Strings.UTF_8)
        String encoded = Base64.DEFAULT.encodeToString(bytes, true)

        def r = new StringReader(encoded)
        String line = ''

        while ((line = r.readLine()) != null) {
            assertTrue line.length() <= 76
        }
    }

    @Test
    void testDecodeFastWithNullArgument() {
        byte[] bytes = Base64.DEFAULT.decodeFast(null)
        assertEquals 0, bytes.length
    }

    @Test
    void testDecodeFastWithEmptyCharArray() {
        byte[] bytes = Base64.DEFAULT.decodeFast(new char[0])
        assertEquals 0, bytes.length
    }

    @Test
    void testDecodeFastWithSurroundingIllegalCharacters() {
        String expected = 'Hello 世界'
        def encoded = '***SGVsbG8g5LiW55WM!!!'
        byte[] bytes = Base64.DEFAULT.decodeFast(encoded.toCharArray())
        String result = new String(bytes, Strings.UTF_8)
        assertEquals expected, result
    }

    @Test
    void testDecodeFastWithLineSeparators() {

        byte[] bytes = PLAINTEXT.getBytes(Strings.UTF_8)
        String encoded = Base64.DEFAULT.encodeToString(bytes, true)

        byte[] resultBytes = Base64.DEFAULT.decodeFast(encoded.toCharArray())

        assertTrue Arrays.equals(bytes, resultBytes)
        assertEquals PLAINTEXT, new String(resultBytes, Strings.UTF_8)
    }

    private static String BASE64(String s) {
        byte[] bytes = s.getBytes(Strings.UTF_8);
        return Base64.DEFAULT.encodeToString(bytes, false)
    }

    @Test // https://tools.ietf.org/html/rfc4648#page-12
    void testRfc4648Base64TestVectors() {

        assertEquals "", BASE64("")

        assertEquals "Zg==", BASE64("f")

        assertEquals "Zm8=", BASE64("fo")

        assertEquals "Zm9v", BASE64("foo")

        assertEquals "Zm9vYg==", BASE64("foob")

        assertEquals "Zm9vYmE=", BASE64("fooba")

        assertEquals "Zm9vYmFy", BASE64("foobar")

        def input = 'special: [\r\n \t], ascii[32..126]: [ !"#$%&\'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~]\n'
        def expected = "c3BlY2lhbDogWw0KIAldLCBhc2NpaVszMi4uMTI2XTogWyAhIiMkJSYnKCkqKywtLi8wMTIzNDU2Nzg5Ojs8PT4/QEFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaW1xdXl9gYWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXp7fH1+XQo="
        assertEquals expected, BASE64(input)
    }

    private static String BASE64URL(String s) {
        byte[] bytes = s.getBytes(Strings.UTF_8);
        return Base64.URL_SAFE.encodeToString(bytes, false)
    }

    @Test //same test vectors above, but with padding removed & some specials swapped: https://brockallen.com/2014/10/17/base64url-encoding/
    void testRfc4648Base64UrlTestVectors() {

        assertEquals "", BASE64URL("")

        assertEquals "Zg", BASE64URL("f") //base64 = 2 padding chars, base64url = no padding needed

        assertEquals "Zm8", BASE64URL("fo") //base64 = 1 padding char, base64url = no padding needed

        assertEquals "Zm9v", BASE64URL("foo")

        assertEquals "Zm9vYg", BASE64URL("foob") //base64 = 2 padding chars, base64url = no padding needed

        assertEquals "Zm9vYmE", BASE64URL("fooba") //base64 = 1 padding char, base64url = no padding needed

        assertEquals "Zm9vYmFy", BASE64URL("foobar")

        def input = 'special: [\r\n \t], ascii[32..126]: [ !"#$%&\'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~]\n'
        def expected = "c3BlY2lhbDogWw0KIAldLCBhc2NpaVszMi4uMTI2XTogWyAhIiMkJSYnKCkqKywtLi8wMTIzNDU2Nzg5Ojs8PT4/QEFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaW1xdXl9gYWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXp7fH1+XQo="
                        .replace("=", "")
                        .replace("+", "-")
                        .replace("/", "_")
        assertEquals expected, BASE64URL(input)
    }
}
