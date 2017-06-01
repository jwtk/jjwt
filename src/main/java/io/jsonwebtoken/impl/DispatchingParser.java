package io.jsonwebtoken.impl;

import io.jsonwebtoken.impl.crypto.*;
import io.jsonwebtoken.lang.Assert;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;

public class DispatchingParser {

    static final char DELIMITER = '.';

    public void parse(String compactJwe) {

        //parse the constituent parts of the compact JWE:

        String base64UrlEncodedHeader = null; //JWT, JWS or JWE

        String base64UrlEncodedCek = null; //JWE only
        String base64UrlEncodedPayload = null; //JWT or JWS

        String base64UrlEncodedIv = null; //JWE only
        String base64UrlEncodedCiphertext = null; //JWE only

        String base64UrlEncodedTag = null; //JWE only
        String base64UrlencodedDigest = null; //JWS only

        StringBuilder sb = new StringBuilder();

        char[] chars = compactJwe.toCharArray();

        int tokenIndex = 0;

        for (char c : chars) {

            Assert.isTrue(!Character.isWhitespace(c), "Compact JWT strings cannot contain whitespace.");

            if (c == DELIMITER) {

                String value = sb.length() > 0 ? sb.toString() : null;

                switch (tokenIndex) {
                    case 0:
                        base64UrlEncodedHeader = value;
                        break;
                    case 1:
                        //we'll figure out if we have a compact JWE or JWS after finishing inspecting the char array:
                        base64UrlEncodedCek = value;
                        base64UrlEncodedPayload = value;
                    case 2:
                        base64UrlEncodedIv = value;
                        break;
                    case 3:
                        base64UrlEncodedCiphertext = value;
                        break;
                }

                sb = new StringBuilder();
                tokenIndex++;
            } else {
                sb.append(c);
            }
        }

        boolean jwe = false;
        if (tokenIndex == 2) { // JWT or JWS
            jwe = false;
        } else if (tokenIndex == 4) { // JWE
            jwe = true;
        } else {
            String msg = "Invalid compact JWT string - invalid number of period character delimiters: " + tokenIndex +
                    ".  JWTs and JWSs must have exactly 2 periods, JWEs must have exactly 4 periods.";
            throw new IllegalArgumentException(msg);
        }

        if (sb.length() > 0) {
            String value = sb.toString();
            if (jwe) {
                base64UrlEncodedTag = value;
            } else {
                base64UrlencodedDigest = value;
            }
        }

        throw new UnsupportedOperationException("Not yet implemented.");

        /*


        base64UrlEncodedTag = sb.toString();

        Assert.notNull(base64UrlEncodedHeader, "Invalid compact JWE: base64Url JWE Protected Header is missing.");
        Assert.notNull(base64UrlEncodedIv, "Invalid compact JWE: base64Url JWE Initialization Vector is missing.");
        Assert.notNull(base64UrlEncodedCiphertext, "Invalid compact JWE: base64Url JWE Ciphertext is missing.");
        Assert.notNull(base64UrlEncodedTag, "Invalid compact JWE: base64Url JWE Authentication Tag is missing.");

        //find which encryption key was used so we can decrypt:
        final byte[] headerBytes = base64UrlDecode(base64UrlEncodedHeader);
        final DefaultHeaders headers = serializationCodec.deserialize(headerBytes, DefaultHeaders.class);

        SecretKey secretKey = secretKeyResolver.getSecretKey(headers);
        if (secretKey == null) {
            String msg = "SecretKeyResolver did not return a secret key for headers " + headers +
                    ".  This is required for message decryption.";
            throw new CryptoException(msg);
        }

        byte[] aad = base64UrlEncodedHeader.getBytes(StandardCharsets.US_ASCII);
        byte[] iv = base64UrlDecode(base64UrlEncodedIv);
        byte[] ciphertext = base64UrlDecode(base64UrlEncodedCiphertext);
        byte[] tag = base64UrlDecode(base64UrlEncodedTag);

        DecryptionRequest dreq = DecryptionRequests.builder()
                .setKey(secretKey.getEncoded())
                .setAdditionalAuthenticatedData(aad)
                .setInitializationVector(iv)
                .setCiphertext(ciphertext)
                .setAuthenticationTag(tag)
                .build();

        byte[] plaintext = encryptionService.decrypt(dreq);

        CompressionAlgorithm calg = headers.getCompressionAlgorithm();
        if (calg != null) {
            plaintext = calg.getCodec().decompress(plaintext);
        }

        Object body = null;

        val = headers.get(JAVA_TYPE_HEADER_NAME);
        if (val != null) {
            String jtyp = val.toString();
            if (jtyp != null) {
                Class bodyType = ClassUtils.forName(jtyp);
                body = serializationCodec.deserialize(plaintext, bodyType);
            }
        }

        message.getHeaders().putAll(headers);
        message.setBody(body);

 */
    }
}
