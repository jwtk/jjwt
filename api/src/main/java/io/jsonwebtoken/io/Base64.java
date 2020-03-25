/*
 * Copyright (C) 2014 jsonwebtoken.io
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
package io.jsonwebtoken.io;

import java.util.Arrays;

/**
 * A very fast and memory efficient class to encode and decode to and from BASE64 or BASE64URL in full accordance
 * with <a href="https://tools.ietf.org/html/rfc4648">RFC 4648</a>.
 *
 * <p>Based initially on MigBase64 with continued modifications for Base64 URL support and JDK-standard code formatting.</p>
 *
 * <p>This encode/decode algorithm doesn't create any temporary arrays as many other codecs do, it only
 * allocates the resulting array. This produces less garbage and it is possible to handle arrays twice
 * as large as algorithms that create a temporary array.</p>
 *
 * <p>There is also a "fast" version of all decode methods that works the same way as the normal ones, but
 * has a few demands on the decoded input. Normally though, these fast versions should be used if the source if
 * the input is known and it hasn't bee tampered with.</p>
 *
 * @author Mikael Grev
 * @author Les Hazlewood
 * @since 0.10.0
 */
@SuppressWarnings("Duplicates")
final class Base64 { //final and package-protected on purpose

    private static final char[] BASE64_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".toCharArray();
    private static final char[] BASE64URL_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_".toCharArray();
    private static final int[] BASE64_IALPHABET = new int[256];
    private static final int[] BASE64URL_IALPHABET = new int[256];
    private static final int IALPHABET_MAX_INDEX = BASE64_IALPHABET.length - 1;

    static {
        Arrays.fill(BASE64_IALPHABET, -1);
        System.arraycopy(BASE64_IALPHABET, 0, BASE64URL_IALPHABET, 0, BASE64_IALPHABET.length);
        for (int i = 0, iS = BASE64_ALPHABET.length; i < iS; i++) {
            BASE64_IALPHABET[BASE64_ALPHABET[i]] = i;
            BASE64URL_IALPHABET[BASE64URL_ALPHABET[i]] = i;
        }
        BASE64_IALPHABET['='] = 0;
        BASE64URL_IALPHABET['='] = 0;
    }

    static final Base64 DEFAULT = new Base64(false);
    static final Base64 URL_SAFE = new Base64(true);

    private final boolean urlsafe;
    private final char[] ALPHABET;
    private final int[] IALPHABET;

    private Base64(boolean urlsafe) {
        this.urlsafe = urlsafe;
        this.ALPHABET = urlsafe ? BASE64URL_ALPHABET : BASE64_ALPHABET;
        this.IALPHABET = urlsafe ? BASE64URL_IALPHABET : BASE64_IALPHABET;
    }

    // ****************************************************************************************
    // *  char[] version
    // ****************************************************************************************

    private String getName() {
        return urlsafe ? "base64url" : "base64"; // RFC 4648 codec names are all lowercase
    }

    /**
     * Encodes a raw byte array into a BASE64 <code>char[]</code> representation in accordance with RFC 2045.
     *
     * @param sArr    The bytes to convert. If <code>null</code> or length 0 an empty array will be returned.
     * @param lineSep Optional "\r\n" after 76 characters, unless end of file.<br>
     *                No line separator will be in breach of RFC 2045 which specifies max 76 per line but will be a
     *                little faster.
     * @return A BASE64 encoded array. Never <code>null</code>.
     */
    private char[] encodeToChar(byte[] sArr, boolean lineSep) {

        // Check special case
        int sLen = sArr != null ? sArr.length : 0;
        if (sLen == 0) {
            return new char[0];
        }

        int eLen = (sLen / 3) * 3; // # of bytes that can encode evenly into 24-bit chunks
        int left = sLen - eLen;    // # of bytes that remain after 24-bit chunking. Always 0, 1 or 2

        int cCnt = (((sLen - 1) / 3 + 1) << 2); // # of base64-encoded characters including padding
        int dLen = cCnt + (lineSep ? (cCnt - 1) / 76 << 1 : 0); // Length of returned char array with padding and any line separators

        int padCount = 0;
        if (left == 2) {
            padCount = 1;
        } else if (left == 1) {
            padCount = 2;
        }

        char[] dArr = new char[urlsafe ? (dLen - padCount) : dLen];

        // Encode even 24-bits
        for (int s = 0, d = 0, cc = 0; s < eLen; ) {

            // Copy next three bytes into lower 24 bits of int, paying attension to sign.
            int i = (sArr[s++] & 0xff) << 16 | (sArr[s++] & 0xff) << 8 | (sArr[s++] & 0xff);

            // Encode the int into four chars
            dArr[d++] = ALPHABET[(i >>> 18) & 0x3f];
            dArr[d++] = ALPHABET[(i >>> 12) & 0x3f];
            dArr[d++] = ALPHABET[(i >>> 6) & 0x3f];
            dArr[d++] = ALPHABET[i & 0x3f];

            // Add optional line separator
            if (lineSep && ++cc == 19 && d < dLen - 2) {
                dArr[d++] = '\r';
                dArr[d++] = '\n';
                cc = 0;
            }
        }

        // Pad and encode last bits if source isn't even 24 bits.
        if (left > 0) {
            // Prepare the int
            int i = ((sArr[eLen] & 0xff) << 10) | (left == 2 ? ((sArr[sLen - 1] & 0xff) << 2) : 0);

            // Set last four chars
            dArr[dLen - 4] = ALPHABET[i >> 12];
            dArr[dLen - 3] = ALPHABET[(i >>> 6) & 0x3f];
            //dArr[dLen - 2] = left == 2 ? ALPHABET[i & 0x3f] : '=';
            //dArr[dLen - 1] = '=';
            if (left == 2) {
                dArr[dLen - 2] = ALPHABET[i & 0x3f];
            } else if (!urlsafe) { // if not urlsafe, we need to include the padding characters
                dArr[dLen - 2] = '=';
            }
            if (!urlsafe) { // include padding
                dArr[dLen - 1] = '=';
            }
        }
        return dArr;
    }

    /*
     * Decodes a BASE64 encoded char array. All illegal characters will be ignored and can handle both arrays with
     * and without line separators.
     *
     * @param sArr The source array. <code>null</code> or length 0 will return an empty array.
     * @return The decoded array of bytes. May be of length 0. Will be <code>null</code> if the legal characters
     * (including '=') isn't divideable by 4.  (I.e. definitely corrupted).
     *
    public final byte[] decode(char[] sArr) {
        // Check special case
        int sLen = sArr != null ? sArr.length : 0;
        if (sLen == 0) {
            return new byte[0];
        }

        // Count illegal characters (including '\r', '\n') to know what size the returned array will be,
        // so we don't have to reallocate & copy it later.
        int sepCnt = 0; // Number of separator characters. (Actually illegal characters, but that's a bonus...)
        for (int i = 0; i < sLen; i++) { // If input is "pure" (I.e. no line separators or illegal chars) base64 this loop can be commented out.
            if (IALPHABET[sArr[i]] < 0) {
                sepCnt++;
            }
        }

        // Check so that legal chars (including '=') are evenly divideable by 4 as specified in RFC 2045.
        if ((sLen - sepCnt) % 4 != 0) {
            return null;
        }

        int pad = 0;
        for (int i = sLen; i > 1 && IALPHABET[sArr[--i]] <= 0; ) {
            if (sArr[i] == '=') {
                pad++;
            }
        }

        int len = ((sLen - sepCnt) * 6 >> 3) - pad;

        byte[] dArr = new byte[len];       // Preallocate byte[] of exact length

        for (int s = 0, d = 0; d < len; ) {
            // Assemble three bytes into an int from four "valid" characters.
            int i = 0;
            for (int j = 0; j < 4; j++) {   // j only increased if a valid char was found.
                int c = IALPHABET[sArr[s++]];
                if (c >= 0) {
                    i |= c << (18 - j * 6);
                } else {
                    j--;
                }
            }
            // Add the bytes
            dArr[d++] = (byte) (i >> 16);
            if (d < len) {
                dArr[d++] = (byte) (i >> 8);
                if (d < len) {
                    dArr[d++] = (byte) i;
                }
            }
        }
        return dArr;
    }
    */

    private int ctoi(char c) {
        int i = c > IALPHABET_MAX_INDEX ? -1 : IALPHABET[c];
        if (i < 0) {
            String msg = "Illegal " + getName() + " character: '" + c + "'";
            throw new DecodingException(msg);
        }
        return i;
    }

    /**
     * Decodes a BASE64 encoded char array that is known to be reasonably well formatted. The preconditions are:<br>
     * + The array must have a line length of 76 chars OR no line separators at all (one line).<br>
     * + Line separator must be "\r\n", as specified in RFC 2045
     * + The array must not contain illegal characters within the encoded string<br>
     * + The array CAN have illegal characters at the beginning and end, those will be dealt with appropriately.<br>
     *
     * @param sArr The source array. Length 0 will return an empty array. <code>null</code> will throw an exception.
     * @return The decoded array of bytes. May be of length 0.
     * @throws DecodingException on illegal input
     */
    final byte[] decodeFast(char[] sArr) throws DecodingException {

        // Check special case
        int sLen = sArr != null ? sArr.length : 0;
        if (sLen == 0) {
            return new byte[0];
        }

        int sIx = 0, eIx = sLen - 1;    // Start and end index after trimming.

        // Trim illegal chars from start
        while (sIx < eIx && IALPHABET[sArr[sIx]] < 0) {
            sIx++;
        }

        // Trim illegal chars from end
        while (eIx > 0 && IALPHABET[sArr[eIx]] < 0) {
            eIx--;
        }

        // get the padding count (=) (0, 1 or 2)
        int pad = sArr[eIx] == '=' ? (sArr[eIx - 1] == '=' ? 2 : 1) : 0;  // Count '=' at end.
        int cCnt = eIx - sIx + 1;   // Content count including possible separators
        int sepCnt = sLen > 76 ? (sArr[76] == '\r' ? cCnt / 78 : 0) << 1 : 0;

        int len = ((cCnt - sepCnt) * 6 >> 3) - pad; // The number of decoded bytes
        byte[] dArr = new byte[len];       // Preallocate byte[] of exact length

        // Decode all but the last 0 - 2 bytes.
        int d = 0;
        for (int cc = 0, eLen = (len / 3) * 3; d < eLen; ) {

            // Assemble three bytes into an int from four "valid" characters.
            int i = ctoi(sArr[sIx++]) << 18 | ctoi(sArr[sIx++]) << 12 | ctoi(sArr[sIx++]) << 6 | ctoi(sArr[sIx++]);

            // Add the bytes
            dArr[d++] = (byte) (i >> 16);
            dArr[d++] = (byte) (i >> 8);
            dArr[d++] = (byte) i;

            // If line separator, jump over it.
            if (sepCnt > 0 && ++cc == 19) {
                sIx += 2;
                cc = 0;
            }
        }

        if (d < len) {
            // Decode last 1-3 bytes (incl '=') into 1-3 bytes
            int i = 0;
            for (int j = 0; sIx <= eIx - pad; j++) {
                i |= ctoi(sArr[sIx++]) << (18 - j * 6);
            }

            for (int r = 16; d < len; r -= 8) {
                dArr[d++] = (byte) (i >> r);
            }
        }

        return dArr;
    }

    // ****************************************************************************************
    // *  byte[] version
    // ****************************************************************************************

    /*
     * Encodes a raw byte array into a BASE64 <code>byte[]</code> representation i accordance with RFC 2045.
     *
     * @param sArr    The bytes to convert. If <code>null</code> or length 0 an empty array will be returned.
     * @param lineSep Optional "\r\n" after 76 characters, unless end of file.<br>
     *                No line separator will be in breach of RFC 2045 which specifies max 76 per line but will be a
     *                little faster.
     * @return A BASE64 encoded array. Never <code>null</code>.
     *
    public final byte[] encodeToByte(byte[] sArr, boolean lineSep) {
        return encodeToByte(sArr, 0, sArr != null ? sArr.length : 0, lineSep);
    }

    /**
     * Encodes a raw byte array into a BASE64 <code>byte[]</code> representation i accordance with RFC 2045.
     *
     * @param sArr    The bytes to convert. If <code>null</code> an empty array will be returned.
     * @param sOff    The starting position in the bytes to convert.
     * @param sLen    The number of bytes to convert. If 0 an empty array will be returned.
     * @param lineSep Optional "\r\n" after 76 characters, unless end of file.<br>
     *                No line separator will be in breach of RFC 2045 which specifies max 76 per line but will be a
     *                little faster.
     * @return A BASE64 encoded array. Never <code>null</code>.
     *
    public final byte[] encodeToByte(byte[] sArr, int sOff, int sLen, boolean lineSep) {

        // Check special case
        if (sArr == null || sLen == 0) {
            return new byte[0];
        }

        int eLen = (sLen / 3) * 3;                              // Length of even 24-bits.
        int cCnt = ((sLen - 1) / 3 + 1) << 2;                   // Returned character count
        int dLen = cCnt + (lineSep ? (cCnt - 1) / 76 << 1 : 0); // Length of returned array
        byte[] dArr = new byte[dLen];

        // Encode even 24-bits
        for (int s = sOff, d = 0, cc = 0; s < sOff + eLen; ) {

            // Copy next three bytes into lower 24 bits of int, paying attension to sign.
            int i = (sArr[s++] & 0xff) << 16 | (sArr[s++] & 0xff) << 8 | (sArr[s++] & 0xff);

            // Encode the int into four chars
            dArr[d++] = (byte) ALPHABET[(i >>> 18) & 0x3f];
            dArr[d++] = (byte) ALPHABET[(i >>> 12) & 0x3f];
            dArr[d++] = (byte) ALPHABET[(i >>> 6) & 0x3f];
            dArr[d++] = (byte) ALPHABET[i & 0x3f];

            // Add optional line separator
            if (lineSep && ++cc == 19 && d < dLen - 2) {
                dArr[d++] = '\r';
                dArr[d++] = '\n';
                cc = 0;
            }
        }

        // Pad and encode last bits if source isn't an even 24 bits.
        int left = sLen - eLen; // 0 - 2.
        if (left > 0) {
            // Prepare the int
            int i = ((sArr[sOff + eLen] & 0xff) << 10) | (left == 2 ? ((sArr[sOff + sLen - 1] & 0xff) << 2) : 0);

            // Set last four chars
            dArr[dLen - 4] = (byte) ALPHABET[i >> 12];
            dArr[dLen - 3] = (byte) ALPHABET[(i >>> 6) & 0x3f];
            dArr[dLen - 2] = left == 2 ? (byte) ALPHABET[i & 0x3f] : (byte) '=';
            dArr[dLen - 1] = '=';
        }
        return dArr;
    }

    /**
     * Decodes a BASE64 encoded byte array. All illegal characters will be ignored and can handle both arrays with
     * and without line separators.
     *
     * @param sArr The source array. Length 0 will return an empty array. <code>null</code> will throw an exception.
     * @return The decoded array of bytes. May be of length 0. Will be <code>null</code> if the legal characters
     * (including '=') isn't divideable by 4. (I.e. definitely corrupted).
     *
    public final byte[] decode(byte[] sArr) {
        return decode(sArr, 0, sArr.length);
    }

    /**
     * Decodes a BASE64 encoded byte array. All illegal characters will be ignored and can handle both arrays with
     * and without line separators.
     *
     * @param sArr The source array. <code>null</code> will throw an exception.
     * @param sOff The starting position in the source array.
     * @param sLen The number of bytes to decode from the source array. Length 0 will return an empty array.
     * @return The decoded array of bytes. May be of length 0. Will be <code>null</code> if the legal characters
     * (including '=') isn't divideable by 4. (I.e. definitely corrupted).
     *
    public final byte[] decode(byte[] sArr, int sOff, int sLen) {

        // Count illegal characters (including '\r', '\n') to know what size the returned array will be,
        // so we don't have to reallocate & copy it later.
        int sepCnt = 0; // Number of separator characters. (Actually illegal characters, but that's a bonus...)
        for (int i = 0; i < sLen; i++) {     // If input is "pure" (I.e. no line separators or illegal chars) base64 this loop can be commented out.
            if (IALPHABET[sArr[sOff + i] & 0xff] < 0) {
                sepCnt++;
            }
        }

        // Check so that legal chars (including '=') are evenly divideable by 4 as specified in RFC 2045.
        if ((sLen - sepCnt) % 4 != 0) {
            return null;
        }

        int pad = 0;
        for (int i = sLen; i > 1 && IALPHABET[sArr[sOff + --i] & 0xff] <= 0; ) {
            if (sArr[sOff + i] == '=') {
                pad++;
            }
        }

        int len = ((sLen - sepCnt) * 6 >> 3) - pad;

        byte[] dArr = new byte[len];       // Preallocate byte[] of exact length

        for (int s = 0, d = 0; d < len; ) {
            // Assemble three bytes into an int from four "valid" characters.
            int i = 0;
            for (int j = 0; j < 4; j++) {   // j only increased if a valid char was found.
                int c = IALPHABET[sArr[sOff + s++] & 0xff];
                if (c >= 0) {
                    i |= c << (18 - j * 6);
                } else {
                    j--;
                }
            }

            // Add the bytes
            dArr[d++] = (byte) (i >> 16);
            if (d < len) {
                dArr[d++] = (byte) (i >> 8);
                if (d < len) {
                    dArr[d++] = (byte) i;
                }
            }
        }

        return dArr;
    }


    /*
     * Decodes a BASE64 encoded byte array that is known to be resonably well formatted. The method is about twice as
     * fast as {@link #decode(byte[])}. The preconditions are:<br>
     * + The array must have a line length of 76 chars OR no line separators at all (one line).<br>
     * + Line separator must be "\r\n", as specified in RFC 2045
     * + The array must not contain illegal characters within the encoded string<br>
     * + The array CAN have illegal characters at the beginning and end, those will be dealt with appropriately.<br>
     *
     * @param sArr The source array. Length 0 will return an empty array. <code>null</code> will throw an exception.
     * @return The decoded array of bytes. May be of length 0.
     *
    public final byte[] decodeFast(byte[] sArr) {

        // Check special case
        int sLen = sArr.length;
        if (sLen == 0) {
            return new byte[0];
        }

        int sIx = 0, eIx = sLen - 1;    // Start and end index after trimming.

        // Trim illegal chars from start
        while (sIx < eIx && IALPHABET[sArr[sIx] & 0xff] < 0) {
            sIx++;
        }

        // Trim illegal chars from end
        while (eIx > 0 && IALPHABET[sArr[eIx] & 0xff] < 0) {
            eIx--;
        }

        // get the padding count (=) (0, 1 or 2)
        int pad = sArr[eIx] == '=' ? (sArr[eIx - 1] == '=' ? 2 : 1) : 0;  // Count '=' at end.
        int cCnt = eIx - sIx + 1;   // Content count including possible separators
        int sepCnt = sLen > 76 ? (sArr[76] == '\r' ? cCnt / 78 : 0) << 1 : 0;

        int len = ((cCnt - sepCnt) * 6 >> 3) - pad; // The number of decoded bytes
        byte[] dArr = new byte[len];       // Preallocate byte[] of exact length

        // Decode all but the last 0 - 2 bytes.
        int d = 0;
        for (int cc = 0, eLen = (len / 3) * 3; d < eLen; ) {

            // Assemble three bytes into an int from four "valid" characters.
            int i = IALPHABET[sArr[sIx++]] << 18 | IALPHABET[sArr[sIx++]] << 12 | IALPHABET[sArr[sIx++]] << 6 | IALPHABET[sArr[sIx++]];

            // Add the bytes
            dArr[d++] = (byte) (i >> 16);
            dArr[d++] = (byte) (i >> 8);
            dArr[d++] = (byte) i;

            // If line separator, jump over it.
            if (sepCnt > 0 && ++cc == 19) {
                sIx += 2;
                cc = 0;
            }
        }

        if (d < len) {
            // Decode last 1-3 bytes (incl '=') into 1-3 bytes
            int i = 0;
            for (int j = 0; sIx <= eIx - pad; j++) {
                i |= IALPHABET[sArr[sIx++]] << (18 - j * 6);
            }

            for (int r = 16; d < len; r -= 8) {
                dArr[d++] = (byte) (i >> r);
            }
        }

        return dArr;
    }
    */

    // ****************************************************************************************
    // * String version
    // ****************************************************************************************

    /**
     * Encodes a raw byte array into a BASE64 <code>String</code> representation i accordance with RFC 2045.
     *
     * @param sArr    The bytes to convert. If <code>null</code> or length 0 an empty array will be returned.
     * @param lineSep Optional "\r\n" after 76 characters, unless end of file.<br>
     *                No line separator will be in breach of RFC 2045 which specifies max 76 per line but will be a
     *                little faster.
     * @return A BASE64 encoded array. Never <code>null</code>.
     */
    final String encodeToString(byte[] sArr, boolean lineSep) {
        // Reuse char[] since we can't create a String incrementally anyway and StringBuffer/Builder would be slower.
        return new String(encodeToChar(sArr, lineSep));
    }

    /*
     * Decodes a BASE64 encoded <code>String</code>. All illegal characters will be ignored and can handle both strings with
     * and without line separators.<br>
     * <b>Note!</b> It can be up to about 2x the speed to call <code>decode(str.toCharArray())</code> instead. That
     * will create a temporary array though. This version will use <code>str.charAt(i)</code> to iterate the string.
     *
     * @param str The source string. <code>null</code> or length 0 will return an empty array.
     * @return The decoded array of bytes. May be of length 0. Will be <code>null</code> if the legal characters
     * (including '=') isn't divideable by 4.  (I.e. definitely corrupted).
     *
    public final byte[] decode(String str) {

        // Check special case
        int sLen = str != null ? str.length() : 0;
        if (sLen == 0) {
            return new byte[0];
        }

        // Count illegal characters (including '\r', '\n') to know what size the returned array will be,
        // so we don't have to reallocate & copy it later.
        int sepCnt = 0; // Number of separator characters. (Actually illegal characters, but that's a bonus...)
        for (int i = 0; i < sLen; i++) { // If input is "pure" (I.e. no line separators or illegal chars) base64 this loop can be commented out.
            if (IALPHABET[str.charAt(i)] < 0) {
                sepCnt++;
            }
        }

        // Check so that legal chars (including '=') are evenly divideable by 4 as specified in RFC 2045.
        if ((sLen - sepCnt) % 4 != 0) {
            return null;
        }

        // Count '=' at end
        int pad = 0;
        for (int i = sLen; i > 1 && IALPHABET[str.charAt(--i)] <= 0; ) {
            if (str.charAt(i) == '=') {
                pad++;
            }
        }

        int len = ((sLen - sepCnt) * 6 >> 3) - pad;

        byte[] dArr = new byte[len];       // Preallocate byte[] of exact length

        for (int s = 0, d = 0; d < len; ) {
            // Assemble three bytes into an int from four "valid" characters.
            int i = 0;
            for (int j = 0; j < 4; j++) {   // j only increased if a valid char was found.
                int c = IALPHABET[str.charAt(s++)];
                if (c >= 0) {
                    i |= c << (18 - j * 6);
                } else {
                    j--;
                }
            }
            // Add the bytes
            dArr[d++] = (byte) (i >> 16);
            if (d < len) {
                dArr[d++] = (byte) (i >> 8);
                if (d < len) {
                    dArr[d++] = (byte) i;
                }
            }
        }
        return dArr;
    }

    /**
     * Decodes a BASE64 encoded string that is known to be resonably well formatted. The method is about twice as
     * fast as {@link #decode(String)}. The preconditions are:<br>
     * + The array must have a line length of 76 chars OR no line separators at all (one line).<br>
     * + Line separator must be "\r\n", as specified in RFC 2045
     * + The array must not contain illegal characters within the encoded string<br>
     * + The array CAN have illegal characters at the beginning and end, those will be dealt with appropriately.<br>
     *
     * @param s The source string. Length 0 will return an empty array. <code>null</code> will throw an exception.
     * @return The decoded array of bytes. May be of length 0.
     *
    public final byte[] decodeFast(String s) {

        // Check special case
        int sLen = s.length();
        if (sLen == 0) {
            return new byte[0];
        }

        int sIx = 0, eIx = sLen - 1;    // Start and end index after trimming.

        // Trim illegal chars from start
        while (sIx < eIx && IALPHABET[s.charAt(sIx) & 0xff] < 0) {
            sIx++;
        }

        // Trim illegal chars from end
        while (eIx > 0 && IALPHABET[s.charAt(eIx) & 0xff] < 0) {
            eIx--;
        }

        // get the padding count (=) (0, 1 or 2)
        int pad = s.charAt(eIx) == '=' ? (s.charAt(eIx - 1) == '=' ? 2 : 1) : 0;  // Count '=' at end.
        int cCnt = eIx - sIx + 1;   // Content count including possible separators
        int sepCnt = sLen > 76 ? (s.charAt(76) == '\r' ? cCnt / 78 : 0) << 1 : 0;

        int len = ((cCnt - sepCnt) * 6 >> 3) - pad; // The number of decoded bytes
        byte[] dArr = new byte[len];       // Preallocate byte[] of exact length

        // Decode all but the last 0 - 2 bytes.
        int d = 0;
        for (int cc = 0, eLen = (len / 3) * 3; d < eLen; ) {
            // Assemble three bytes into an int from four "valid" characters.
            int i = IALPHABET[s.charAt(sIx++)] << 18 | IALPHABET[s.charAt(sIx++)] << 12 | IALPHABET[s.charAt(sIx++)] << 6 | IALPHABET[s.charAt(sIx++)];

            // Add the bytes
            dArr[d++] = (byte) (i >> 16);
            dArr[d++] = (byte) (i >> 8);
            dArr[d++] = (byte) i;

            // If line separator, jump over it.
            if (sepCnt > 0 && ++cc == 19) {
                sIx += 2;
                cc = 0;
            }
        }

        if (d < len) {
            // Decode last 1-3 bytes (incl '=') into 1-3 bytes
            int i = 0;
            for (int j = 0; sIx <= eIx - pad; j++) {
                i |= IALPHABET[s.charAt(sIx++)] << (18 - j * 6);
            }

            for (int r = 16; d < len; r -= 8) {
                dArr[d++] = (byte) (i >> r);
            }
        }

        return dArr;
    }
    */
}
