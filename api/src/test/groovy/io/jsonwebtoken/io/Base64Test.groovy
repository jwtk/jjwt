package io.jsonwebtoken.io

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
    void testBase64Name() {
        assertEquals 'base64', Base64.DEFAULT.getName() // RFC 4648 codec name is all lowercase
    }

    @Test
    void testBase64UrlName() {
        assertEquals 'base64url', Base64.URL_SAFE.getName() // RFC 4648 codec name is all lowercase
    }

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
    void testDecodeFastWithIntermediateIllegalInboundCharacters() {
        def encoded = 'SGVsbG8g*5LiW55WM'
        try {
            Base64.DEFAULT.decodeFast(encoded.toCharArray())
            fail()
        } catch (DecodingException de) {
            assertEquals 'Illegal base64 character: \'*\'', de.getMessage()
        }
    }

    @Test
    void testDecodeFastWithIntermediateIllegalOutOfBoundCharacters() {
        def encoded = 'SGVsbG8g世5LiW55WM'
        try {
            Base64.DEFAULT.decodeFast(encoded.toCharArray())
            fail()
        } catch (DecodingException de) {
            assertEquals 'Illegal base64 character: \'世\'', de.getMessage()
        }
    }

    @Test
    void testDecodeFastWithIntermediateIllegalSpaceCharacters() {
        def encoded = 'SGVsbG8g 5LiW55WM'
        try {
            Base64.DEFAULT.decodeFast(encoded.toCharArray())
            fail()
        } catch (DecodingException de) {
            assertEquals 'Illegal base64 character: \' \'', de.getMessage()
        }
    }

    @Test
    void testDecodeFastWithLineSeparators() {

        byte[] bytes = PLAINTEXT.getBytes(Strings.UTF_8)
        String encoded = Base64.DEFAULT.encodeToString(bytes, true)

        byte[] resultBytes = Base64.DEFAULT.decodeFast(encoded.toCharArray())

        assertTrue Arrays.equals(bytes, resultBytes)
        assertEquals PLAINTEXT, new String(resultBytes, Strings.UTF_8)
    }

    private static String encode(String s) {
        byte[] bytes = s.getBytes(Strings.UTF_8);
        return Base64.DEFAULT.encodeToString(bytes, false)
    }

    private static String decode(String s) {
        byte[] bytes = Base64.DEFAULT.decodeFast(s.toCharArray())
        return new String(bytes, Strings.UTF_8)
    }

    @Test // https://tools.ietf.org/html/rfc4648#page-12
    void testRfc4648Base64TestVectors() {

        assertEquals "", encode("")
        assertEquals "", decode("")

        assertEquals "Zg==", encode("f")
        assertEquals "f", decode("Zg==")

        assertEquals "Zm8=", encode("fo")
        assertEquals "fo", decode("Zm8=")

        assertEquals "Zm9v", encode("foo")
        assertEquals "foo", decode("Zm9v")

        assertEquals "Zm9vYg==", encode("foob")
        assertEquals "foob", decode("Zm9vYg==")

        assertEquals "Zm9vYmE=", encode("fooba")
        assertEquals "fooba", decode("Zm9vYmE=")

        assertEquals "Zm9vYmFy", encode("foobar")
        assertEquals "foobar", decode("Zm9vYmFy")

        def input = 'special: [\r\n \t], ascii[32..126]: [ !"#$%&\'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~]\n'
        def expected = "c3BlY2lhbDogWw0KIAldLCBhc2NpaVszMi4uMTI2XTogWyAhIiMkJSYnKCkqKywtLi8wMTIzNDU2Nzg5Ojs8PT4/QEFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaW1xdXl9gYWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXp7fH1+XQo="
        assertEquals expected, encode(input)
        assertEquals input, decode(expected)
    }

    private static String urlEncode(String s) {
        byte[] bytes = s.getBytes(Strings.UTF_8);
        return Base64.URL_SAFE.encodeToString(bytes, false)
    }

    private static String urlDecode(String s) {
        byte[] bytes = Base64.URL_SAFE.decodeFast(s.toCharArray())
        return new String(bytes, Strings.UTF_8)
    }

    @Test //same test vectors above, but with padding removed & some specials swapped: https://brockallen.com/2014/10/17/base64url-encoding/
    void testRfc4648Base64UrlTestVectors() {

        assertEquals "", urlEncode("")
        assertEquals "", urlDecode("")

        assertEquals "Zg", urlEncode("f") //base64 = 2 padding chars, base64url = no padding needed
        assertEquals "f", urlDecode("Zg")

        assertEquals "Zm8", urlEncode("fo") //base64 = 1 padding char, base64url = no padding needed
        assertEquals "fo", urlDecode("Zm8")

        assertEquals "Zm9v", urlEncode("foo")
        assertEquals "foo", urlDecode("Zm9v")

        assertEquals "Zm9vYg", urlEncode("foob") //base64 = 2 padding chars, base64url = no padding needed
        assertEquals "foob", urlDecode("Zm9vYg")

        assertEquals "Zm9vYmE", urlEncode("fooba") //base64 = 1 padding char, base64url = no padding needed
        assertEquals "fooba", urlDecode("Zm9vYmE")

        assertEquals "Zm9vYmFy", urlEncode("foobar")
        assertEquals "foobar", urlDecode("Zm9vYmFy")

        def input = 'special: [\r\n \t], ascii[32..126]: [ !"#$%&\'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~]\n'
        def expected = "c3BlY2lhbDogWw0KIAldLCBhc2NpaVszMi4uMTI2XTogWyAhIiMkJSYnKCkqKywtLi8wMTIzNDU2Nzg5Ojs8PT4/QEFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaW1xdXl9gYWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXp7fH1+XQo="
                        .replace("=", "")
                        .replace("+", "-")
                        .replace("/", "_")
        assertEquals expected, urlEncode(input)
        assertEquals input, urlDecode(expected)
    }
}
