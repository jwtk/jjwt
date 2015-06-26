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
package io.jsonwebtoken.impl;

public class Base64UrlCodec extends AbstractTextCodec {

    @Override
    public String encode(byte[] data) {
        String base64Text = TextCodec.BASE64.encode(data);
        byte[] bytes = base64Text.getBytes(US_ASCII);

        //base64url encoding doesn't use padding chars:
        bytes = removePadding(bytes);

        //replace URL-unfriendly Base64 chars to url-friendly ones:
        for (int i = 0; i < bytes.length; i++) {
            if (bytes[i] == '+') {
                bytes[i] = '-';
            } else if (bytes[i] == '/') {
                bytes[i] = '_';
            }
        }

        return new String(bytes, US_ASCII);
    }

    protected byte[] removePadding(byte[] bytes) {

        byte[] result = bytes;

        int paddingCount = 0;
        for (int i = bytes.length - 1; i > 0; i--) {
            if (bytes[i] == '=') {
                paddingCount++;
            } else {
                break;
            }
        }
        if (paddingCount > 0) {
            result = new byte[bytes.length - paddingCount];
            System.arraycopy(bytes, 0, result, 0, bytes.length - paddingCount);
        }

        return result;
    }

    @Override
    public byte[] decode(String encoded) {
        char[] chars = encoded.toCharArray(); //always ASCII - one char == 1 byte

        //Base64 requires padding to be in place before decoding, so add it if necessary:
        chars = ensurePadding(chars);

        //Replace url-friendly chars back to normal Base64 chars:
        for (int i = 0; i < chars.length; i++) {
            if (chars[i] == '-') {
                chars[i] = '+';
            } else if (chars[i] == '_') {
                chars[i] = '/';
            }
        }

        String base64Text = new String(chars);

        return TextCodec.BASE64.decode(base64Text);
    }

    protected char[] ensurePadding(char[] chars) {

        char[] result = chars; //assume argument in case no padding is necessary

        int paddingCount = 0;

        //fix for https://github.com/jwtk/jjwt/issues/31
        int remainder = chars.length % 4;
        if (remainder == 2 || remainder == 3) {
            paddingCount = 4 - remainder;
        }

        if (paddingCount > 0) {
            result = new char[chars.length + paddingCount];
            System.arraycopy(chars, 0, result, 0, chars.length);
            for (int i = 0; i < paddingCount; i++) {
                result[chars.length + i] = '=';
            }
        }

        return result;
    }

}
