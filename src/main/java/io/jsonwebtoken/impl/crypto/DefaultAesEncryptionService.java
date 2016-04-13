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
package io.jsonwebtoken.impl.crypto;

import io.jsonwebtoken.lang.Arrays;
import io.jsonwebtoken.lang.Assert;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

/**
 * Default {@link EncryptionService} implementation that uses AES in GCM mode.
 */
public class DefaultAesEncryptionService implements EncryptionService {

    private static final int GCM_TAG_SIZE = 16; //number of bytes, not bits. Highest for GCM is 128 bits and recommended
    private static final int GCM_NONCE_SIZE = 12; //number of bytes, not bits. 12 is recommended for GCM for efficiency

    public static final SecureRandom DEFAULT_RANDOM = new SecureRandom();
    protected static final String DECRYPT_NO_IV = "This EncryptionService implementation rejects decryption " +
            "requests that do not include initialization vectors.  AES " +
            "ciphertext without an IV is weak and should never be used.";

    private final SecretKey key;

    private final SecureRandom random;

    public DefaultAesEncryptionService(byte[] key) {
        this(key, DEFAULT_RANDOM);
    }

    public DefaultAesEncryptionService(byte[] key, SecureRandom random) {
        Assert.notEmpty(key, "Encryption key cannot be null or empty.");
        Assert.notNull(random, "SecureRandom instance cannot be null or empty.");
        this.key = new SecretKeySpec(key, "AES");
        this.random = random;
    }

    @Override
    public byte[] encrypt(byte[] plaintext) {
        EncryptionRequest req = EncryptionRequests.builder().setPlaintext(plaintext).build();
        EncryptionResult res = encrypt(req);
        return res.compact();
    }

    protected Cipher newCipher() throws NoSuchPaddingException, NoSuchAlgorithmException {
        return Cipher.getInstance("AES/GCM/NoPadding");
    }

    protected Cipher newCipher(int mode, byte[] nonce, SecretKey key)
            throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException,
            InvalidKeyException {

        Cipher aesGcm = newCipher();

        GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_SIZE * Byte.SIZE, nonce);

        aesGcm.init(mode, key, spec);

        return aesGcm;
    }

    @Override
    public byte[] decrypt(byte[] compact) {
        byte[] nonce = getCiphertextNonce(compact);
        byte[] ciphertext = getTaggedCiphertext(compact);
        DecryptionRequest req = DecryptionRequests.builder()
                .setInitializationVector(nonce).setCiphertext(ciphertext).build();
        return decrypt(req);
    }

    protected byte[] getCiphertextNonce(byte[] ciphertext) {
        byte[] nonce = new byte[GCM_NONCE_SIZE];
        System.arraycopy(ciphertext, 0, nonce, 0, GCM_NONCE_SIZE);
        return nonce;
    }

    protected byte[] getTaggedCiphertext(byte[] ciphertext) {
        int taggedCiphertextLength = ciphertext.length - GCM_NONCE_SIZE;
        byte[] taggedCipherText = new byte[taggedCiphertextLength];
        //remaining data is the tagged ciphertext.  Isolate it:
        System.arraycopy(ciphertext, GCM_NONCE_SIZE, taggedCipherText, 0, taggedCiphertextLength);
        return taggedCipherText;
    }

    @Override
    public EncryptionResult encrypt(EncryptionRequest req) throws CryptoException {
        try {
            Assert.notNull(req, "EncryptionRequest cannot be null.");
            return doEncrypt(req);
        } catch (Exception e) {
            String msg = "Unable to perform encryption: " + e.getMessage();
            throw new CryptoException(msg, e);
        }
    }

    protected EncryptionResult doEncrypt(EncryptionRequest req)
            throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, InvalidKeyException,
            NoSuchPaddingException, BadPaddingException, IllegalBlockSizeException {

        //Ensure IV:
        byte[] iv = req.getInitializationVector();
        int ivLength = Arrays.length(iv);
        if (ivLength == 0) {
            iv = new byte[GCM_NONCE_SIZE]; //for AES GCM, the IV is often called the nonce
            random.nextBytes(iv);
        }

        //Ensure Key:
        SecretKey key = this.key;
        byte[] keyBytes = req.getKey();
        int keyBytesLength = Arrays.length(keyBytes);
        if (keyBytesLength > 0) {
            key = new SecretKeySpec(keyBytes, "AES");
        }

        Cipher aesGcm = newCipher(Cipher.ENCRYPT_MODE, iv, key);

        //Support Additional Associated Data if necessary:
        int aadLength = 0;
        if (req instanceof AssociatedDataSource) {
            byte[] aad = ((AssociatedDataSource) req).getAssociatedData();
            aadLength = Arrays.length(aad);
            if (aadLength > 0) {
                aesGcm.updateAAD(aad);
            }
        }

        //now for the actual encryption:
        byte[] plaintext = req.getPlaintext();
        byte[] ciphertext = aesGcm.doFinal(plaintext);

        if (aadLength > 0) { //authenticated

            byte[] taggedCiphertext = ciphertext; //ciphertext is actually tagged

            //separate the tag from the ciphertext:
            int ciphertextLength = taggedCiphertext.length - GCM_TAG_SIZE;
            ciphertext = new byte[ciphertextLength];
            System.arraycopy(taggedCiphertext, 0, ciphertext, 0, ciphertextLength);

            byte[] tag = new byte[GCM_TAG_SIZE];
            System.arraycopy(taggedCiphertext, ciphertextLength, tag, 0, GCM_TAG_SIZE);
            return new DefaultAuthenticatedEncryptionResult(iv, ciphertext, tag);
        }

        return new DefaultEncryptionResult(iv, ciphertext);

    }

    @Override
    public byte[] decrypt(DecryptionRequest req) throws CryptoException {
        try {
            Assert.notNull(req, "DecryptionRequest cannot be null.");
            return doDecrypt(req);
        } catch (Exception e) {
            String msg = "Unable to perform decryption: " + e.getMessage();
            throw new CryptoException(msg, e);
        }
    }

    protected byte[] doDecrypt(DecryptionRequest req)
            throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, InvalidKeyException,
            NoSuchPaddingException, BadPaddingException, IllegalBlockSizeException {

        byte[] iv = req.getInitializationVector();
        Assert.notEmpty(iv, DECRYPT_NO_IV);

        //Ensure Key:
        SecretKey key = this.key;
        byte[] keyBytes = req.getKey();
        if (keyBytes != null && keyBytes.length > 0) {
            key = new SecretKeySpec(keyBytes, "AES");
        }

        final byte[] ciphertext = req.getCiphertext();
        byte[] finalBytes = ciphertext; //by default, unless there is an authentication tag

        Cipher aesGcm = newCipher(Cipher.DECRYPT_MODE, iv, key);

        //Support Additional Associated Data:
        if (req instanceof AuthenticatedDecryptionRequest) {

            AuthenticatedDecryptionRequest areq = (AuthenticatedDecryptionRequest) req;

            byte[] aad = areq.getAssociatedData();
            Assert.notEmpty(aad, "AuthenticatedDecryptionRRequests must include Additional Authenticated Data.");

            aesGcm.updateAAD(aad);

            //for tagged GCM, the JVM spec requires that the tag be appended to the end of the ciphertext
            //byte array.  So we'll append it here:

            byte[] tag = areq.getAuthenticationTag();
            Assert.notEmpty(tag, "AuthenticatedDecryptionReqeusts must include an authentication tag.");

            byte[] taggedCiphertext = new byte[ciphertext.length + tag.length];
            System.arraycopy(ciphertext, 0, taggedCiphertext, 0, ciphertext.length);

            System.arraycopy(tag, 0, taggedCiphertext, ciphertext.length, tag.length);

            finalBytes = taggedCiphertext;
        }

        return aesGcm.doFinal(finalBytes);
    }
}
