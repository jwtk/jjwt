package io.jsonwebtoken.impl;

import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.lang.Assert;

public class JwtTokenizer {

    static final char DELIMITER = '.';

    private static final String DELIM_ERR_MSG_PREFIX = "Invalid compact JWT string: Compact JWSs must contain " +
        "exactly 2 period characters, and compact JWEs must contain exactly 4.  Found: ";

    @SuppressWarnings("unchecked")
    public <T extends TokenizedJwt> T tokenize(String jwt) {

        Assert.hasText(jwt, "Argument cannot be null or empty.");

        String protectedHeader = ""; //Both JWS and JWE
        String body = ""; //JWS Payload or JWE Ciphertext
        String encryptedKey = ""; //JWE only
        String iv = ""; //JWE only
        String digest; //JWS Signature or JWE AAD Tag

        int delimiterCount = 0;

        StringBuilder sb = new StringBuilder(128);

        for (char c : jwt.toCharArray()) {

            if (Character.isWhitespace(c)) {
                String msg = "Compact JWT strings may not contain whitespace.";
                throw new MalformedJwtException(msg);
            }

            if (c == DELIMITER) {

                String token = sb.toString();

                switch (delimiterCount) {
                    case 0:
                        protectedHeader = token;
                        break;
                    case 1:
                        body = token; //for JWS
                        encryptedKey = token; //for JWE
                        break;
                    case 2:
                        body = ""; //clear out value set for JWS
                        iv = token;
                        break;
                    case 3:
                        body = token;
                        break;
                }

                sb.setLength(0);
                delimiterCount++;
            } else {
                sb.append(c);
            }
        }

        if (delimiterCount != 2 && delimiterCount != 4) {
            String msg = DELIM_ERR_MSG_PREFIX + delimiterCount;
            throw new MalformedJwtException(msg);
        }

        digest = sb.toString();

        if (delimiterCount == 2) {
            return (T) new DefaultTokenizedJwt(protectedHeader, body, digest);
        }

        return (T) new DefaultTokenizedJwe(protectedHeader, body, digest, encryptedKey, iv);
    }
}
