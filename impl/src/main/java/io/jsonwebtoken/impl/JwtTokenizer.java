/*
 * Copyright (C) 2021 jsonwebtoken.io
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

import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.impl.io.Streams;
import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.lang.Strings;

import java.io.IOException;
import java.io.Reader;

public class JwtTokenizer {

    static final char DELIMITER = '.';

    private static final String DELIM_ERR_MSG_PREFIX = "Invalid compact JWT string: Compact JWSs must contain " +
            "exactly 2 period characters, and compact JWEs must contain exactly 4.  Found: ";

    private static int read(Reader r, char[] buf) {
        try {
            return r.read(buf);
        } catch (IOException e) {
            String msg = "Unable to read compact JWT: " + e.getMessage();
            throw new MalformedJwtException(msg, e);
        }
    }

    @SuppressWarnings("unchecked")
    public <T extends TokenizedJwt> T tokenize(Reader reader) {

        Assert.notNull(reader, "Reader argument cannot be null.");

        CharSequence protectedHeader = Strings.EMPTY; //Both JWS and JWE
        CharSequence body = Strings.EMPTY; //JWS payload or JWE Ciphertext
        CharSequence encryptedKey = Strings.EMPTY; //JWE only
        CharSequence iv = Strings.EMPTY; //JWE only
        CharSequence digest = Strings.EMPTY; //JWS Signature or JWE AAD Tag

        int delimiterCount = 0;
        char[] buf = new char[4096];
        int len = 0;
        StringBuilder sb = new StringBuilder(4096);
        while (len != Streams.EOF) {

            len = read(reader, buf);

            for (int i = 0; i < len; i++) {

                char c = buf[i];

                if (Character.isWhitespace(c)) {
                    String msg = "Compact JWT strings may not contain whitespace.";
                    throw new MalformedJwtException(msg);
                }

                if (c == DELIMITER) {

                    CharSequence seq = Strings.clean(sb);
                    String token = seq != null ? seq.toString() : Strings.EMPTY;

                    switch (delimiterCount) {
                        case 0:
                            protectedHeader = token;
                            break;
                        case 1:
                            body = token; //for JWS
                            encryptedKey = token; //for JWE
                            break;
                        case 2:
                            body = Strings.EMPTY; //clear out value set for JWS
                            iv = token;
                            break;
                        case 3:
                            body = token;
                            break;
                    }

                    delimiterCount++;
                    sb.setLength(0);
                } else {
                    sb.append(c);
                }
            }
        }

        if (delimiterCount != 2 && delimiterCount != 4) {
            String msg = DELIM_ERR_MSG_PREFIX + delimiterCount;
            throw new MalformedJwtException(msg);
        }

        if (sb.length() > 0) {
            digest = sb.toString();
        }

        if (delimiterCount == 2) {
            return (T) new DefaultTokenizedJwt(protectedHeader, body, digest);
        }

        return (T) new DefaultTokenizedJwe(protectedHeader, body, digest, encryptedKey, iv);
    }
}
