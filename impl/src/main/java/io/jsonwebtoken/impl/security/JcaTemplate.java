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
package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.Identifiable;
import io.jsonwebtoken.impl.lang.Bytes;
import io.jsonwebtoken.impl.lang.CheckedFunction;
import io.jsonwebtoken.impl.lang.CheckedSupplier;
import io.jsonwebtoken.impl.lang.DefaultRegistry;
import io.jsonwebtoken.impl.lang.Function;
import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.lang.Collections;
import io.jsonwebtoken.lang.Objects;
import io.jsonwebtoken.lang.Registry;
import io.jsonwebtoken.lang.Strings;
import io.jsonwebtoken.security.SecurityException;
import io.jsonwebtoken.security.SignatureException;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

public class JcaTemplate {

    private static final List<InstanceFactory<?>> FACTORIES = Collections.<InstanceFactory<?>>of(
            new CipherFactory(),
            new KeyFactoryFactory(),
            new SecretKeyFactoryFactory(),
            new KeyGeneratorFactory(),
            new KeyPairGeneratorFactory(),
            new KeyAgreementFactory(),
            new MessageDigestFactory(),
            new SignatureFactory(),
            new MacFactory(),
            new AlgorithmParametersFactory(),
            new CertificateFactoryFactory()
    );

    private static final Registry<Class<?>, InstanceFactory<?>> REGISTRY = new DefaultRegistry<>(
            "JCA Instance Factory", "instance class", FACTORIES,
            new Function<InstanceFactory<?>, Class<?>>() {
                @Override
                public Class<?> apply(InstanceFactory<?> factory) {
                    return factory.getInstanceClass();
                }
            });

    // visible for testing
    protected Provider findBouncyCastle() {
        return Providers.findBouncyCastle();
    }

    private final String jcaName;
    private final Provider provider;
    private final SecureRandom secureRandom;

    JcaTemplate(String jcaName) {
        this(jcaName, null);
    }

    JcaTemplate(String jcaName, Provider provider) {
        this(jcaName, provider, null);
    }

    JcaTemplate(String jcaName, Provider provider, SecureRandom secureRandom) {
        this.jcaName = Assert.hasText(jcaName, "jcaName string cannot be null or empty.");
        this.secureRandom = secureRandom != null ? secureRandom : Randoms.secureRandom();
        this.provider = provider; //may be null, meaning to use the JCA subsystem default provider
    }

    private <T, R> R execute(Class<T> clazz, CheckedFunction<T, R> callback, Provider provider) throws Exception {
        InstanceFactory<?> factory = REGISTRY.get(clazz);
        Assert.notNull(factory, "Unsupported JCA instance class.");

        Object object = factory.get(this.jcaName, provider);
        T instance = Assert.isInstanceOf(clazz, object, "Factory instance does not match expected type.");

        return callback.apply(instance);
    }

    private <T> T execute(Class<?> clazz, CheckedSupplier<T> fn) throws SecurityException {
        try {
            return fn.get();
        } catch (SecurityException se) {
            throw se; //propagate
        } catch (Throwable t) {
            String msg = clazz.getSimpleName() + " callback execution failed: " + t.getMessage();
            throw new SecurityException(msg, t);
        }
    }

    private <T, R> R execute(final Class<T> clazz, final CheckedFunction<T, R> fn) throws SecurityException {
        return execute(clazz, new CheckedSupplier<R>() {
            @Override
            public R get() throws Exception {
                return execute(clazz, fn, JcaTemplate.this.provider);
            }
        });
    }

    protected <T, R> R fallback(final Class<T> clazz, final CheckedFunction<T, R> callback) throws SecurityException {
        return execute(clazz, new CheckedSupplier<R>() {
            @Override
            public R get() throws Exception {
                try {
                    return execute(clazz, callback, JcaTemplate.this.provider);
                } catch (Exception e) {
                    try { // fallback
                        Provider bc = findBouncyCastle();
                        if (bc != null) {
                            return execute(clazz, callback, bc);
                        }
                    } catch (Throwable ignored) { // report original exception instead
                    }
                    throw e;
                }
            }
        });
    }

    public <R> R withCipher(CheckedFunction<Cipher, R> fn) throws SecurityException {
        return execute(Cipher.class, fn);
    }

    public <R> R withKeyFactory(CheckedFunction<KeyFactory, R> fn) throws SecurityException {
        return execute(KeyFactory.class, fn);
    }

    public <R> R withSecretKeyFactory(CheckedFunction<SecretKeyFactory, R> fn) throws SecurityException {
        return execute(SecretKeyFactory.class, fn);
    }

    public <R> R withKeyGenerator(CheckedFunction<KeyGenerator, R> fn) throws SecurityException {
        return execute(KeyGenerator.class, fn);
    }

    public <R> R withKeyAgreement(CheckedFunction<KeyAgreement, R> fn) throws SecurityException {
        return execute(KeyAgreement.class, fn);
    }

    public <R> R withKeyPairGenerator(CheckedFunction<KeyPairGenerator, R> fn) throws SecurityException {
        return execute(KeyPairGenerator.class, fn);
    }

    public <R> R withMessageDigest(CheckedFunction<MessageDigest, R> fn) throws SecurityException {
        return execute(MessageDigest.class, fn);
    }

    public <R> R withSignature(CheckedFunction<Signature, R> fn) throws SecurityException {
        return execute(Signature.class, fn);
    }

    public <R> R withMac(CheckedFunction<Mac, R> fn) throws SecurityException {
        return execute(Mac.class, fn);
    }

    public <R> R withAlgorithmParameters(CheckedFunction<AlgorithmParameters, R> fn) throws SecurityException {
        return execute(AlgorithmParameters.class, fn);
    }

    public <R> R withCertificateFactory(CheckedFunction<CertificateFactory, R> fn) throws SecurityException {
        return execute(CertificateFactory.class, fn);
    }

    public SecretKey generateSecretKey(final int keyBitLength) {
        return withKeyGenerator(new CheckedFunction<KeyGenerator, SecretKey>() {
            @Override
            public SecretKey apply(KeyGenerator generator) {
                generator.init(keyBitLength, secureRandom);
                return generator.generateKey();
            }
        });
    }

    public KeyPair generateKeyPair() {
        return withKeyPairGenerator(new CheckedFunction<KeyPairGenerator, KeyPair>() {
            @Override
            public KeyPair apply(KeyPairGenerator gen) {
                return gen.generateKeyPair();
            }
        });
    }

    public KeyPair generateKeyPair(final int keyBitLength) {
        return withKeyPairGenerator(new CheckedFunction<KeyPairGenerator, KeyPair>() {
            @Override
            public KeyPair apply(KeyPairGenerator generator) {
                generator.initialize(keyBitLength, secureRandom);
                return generator.generateKeyPair();
            }
        });
    }

    public KeyPair generateKeyPair(final AlgorithmParameterSpec params) {
        return withKeyPairGenerator(new CheckedFunction<KeyPairGenerator, KeyPair>() {
            @Override
            public KeyPair apply(KeyPairGenerator generator) throws InvalidAlgorithmParameterException {
                generator.initialize(params, secureRandom);
                return generator.generateKeyPair();
            }
        });
    }

    public PublicKey generatePublic(final KeySpec spec) {
        return fallback(KeyFactory.class, new CheckedFunction<KeyFactory, PublicKey>() {
            @Override
            public PublicKey apply(KeyFactory keyFactory) throws Exception {
                return keyFactory.generatePublic(spec);
            }
        });
    }

    protected boolean isJdk11() {
        return System.getProperty("java.version").startsWith("11");
    }

    private boolean isJdk8213363Bug(InvalidKeySpecException e) {
        return isJdk11() &&
                ("XDH".equals(this.jcaName) || "X25519".equals(this.jcaName) || "X448".equals(this.jcaName)) &&
                e.getCause() instanceof InvalidKeyException &&
                !Objects.isEmpty(e.getStackTrace()) &&
                "sun.security.ec.XDHKeyFactory".equals(e.getStackTrace()[0].getClassName()) &&
                "engineGeneratePrivate".equals(e.getStackTrace()[0].getMethodName());
    }

    // visible for testing
    private int getJdk8213363BugExpectedSize(InvalidKeyException e) {
        String msg = e.getMessage();
        String prefix = "key length must be ";
        if (Strings.hasText(msg) && msg.startsWith(prefix)) {
            String expectedSizeString = msg.substring(prefix.length());
            try {
                return Integer.parseInt(expectedSizeString);
            } catch (NumberFormatException ignored) { // return -1 below
            }
        }
        return -1;
    }

    private KeySpec respecIfNecessary(InvalidKeySpecException e, KeySpec spec) {
        if (!(spec instanceof PKCS8EncodedKeySpec)) {
            return null;
        }
        PKCS8EncodedKeySpec pkcs8Spec = (PKCS8EncodedKeySpec) spec;
        byte[] encoded = pkcs8Spec.getEncoded();

        // Address the [JDK 11 SunCE provider bug](https://bugs.openjdk.org/browse/JDK-8213363) for X25519
        // and X448 encoded keys: Even though the key material might be encoded properly, JDK 11's
        // SunCE provider incorrectly expects an ASN.1 OCTET STRING (without the DER tag/length prefix)
        // when it should actually be a BER-encoded OCTET STRING (with the tag/length prefix).
        // So we get the raw key bytes and use our key factory method:
        if (isJdk8213363Bug(e)) {
            InvalidKeyException cause = // asserted in isJdk8213363Bug method
                    Assert.isInstanceOf(InvalidKeyException.class, e.getCause(), "Unexpected argument.");
            int size = getJdk8213363BugExpectedSize(cause);
            if ((size == 32 || size == 56) && Bytes.length(encoded) >= size) {
                byte[] adjusted = new byte[size];
                System.arraycopy(encoded, encoded.length - size, adjusted, 0, size);
                EdwardsCurve curve = size == 32 ? EdwardsCurve.X25519 : EdwardsCurve.X448;
                return curve.privateKeySpec(adjusted, false);
            }
        }

        return null;
    }

    // visible for testing
    protected PrivateKey generatePrivate(KeyFactory factory, KeySpec spec) throws InvalidKeySpecException {
        return factory.generatePrivate(spec);
    }

    public PrivateKey generatePrivate(final KeySpec spec) {
        return fallback(KeyFactory.class, new CheckedFunction<KeyFactory, PrivateKey>() {
            @Override
            public PrivateKey apply(KeyFactory keyFactory) throws Exception {
                try {
                    return generatePrivate(keyFactory, spec);
                } catch (InvalidKeySpecException e) {
                    KeySpec respec = respecIfNecessary(e, spec);
                    if (respec != null) {
                        return generatePrivate(keyFactory, respec);
                    }
                    throw e; // could not respec, propagate
                }
            }
        });
    }

    public X509Certificate generateX509Certificate(final byte[] x509DerBytes) {
        return fallback(CertificateFactory.class, new CheckedFunction<CertificateFactory, X509Certificate>() {
            @Override
            public X509Certificate apply(CertificateFactory cf) throws CertificateException {
                InputStream is = new ByteArrayInputStream(x509DerBytes);
                return (X509Certificate) cf.generateCertificate(is);
            }
        });
    }

    private interface InstanceFactory<T> extends Identifiable {

        Class<T> getInstanceClass();

        T get(String jcaName, Provider provider) throws Exception;
    }

    private static abstract class JcaInstanceFactory<T> implements InstanceFactory<T> {

        private final Class<T> clazz;

        // Boolean value: missing/null = haven't attempted, true = attempted and succeeded, false = attempted and failed
        private final ConcurrentMap<String, Boolean> FALLBACK_ATTEMPTS = new ConcurrentHashMap<>();

        JcaInstanceFactory(Class<T> clazz) {
            this.clazz = Assert.notNull(clazz, "Class argument cannot be null.");
        }

        @Override
        public Class<T> getInstanceClass() {
            return this.clazz;
        }

        @Override
        public String getId() {
            return clazz.getSimpleName();
        }

        // visible for testing
        protected Provider findBouncyCastle() {
            return Providers.findBouncyCastle();
        }

        @SuppressWarnings("GrazieInspection")
        @Override
        public final T get(String jcaName, final Provider specifiedProvider) throws Exception {
            Assert.hasText(jcaName, "jcaName cannot be null or empty.");
            Provider provider = specifiedProvider;
            final Boolean attempted = FALLBACK_ATTEMPTS.get(jcaName);
            if (provider == null && attempted != null && attempted) {
                // We tried with the default provider previously, and needed to fallback, so just
                // preemptively load the fallback to avoid the fallback/retry again:
                provider = findBouncyCastle();
            }
            try {
                return doGet(jcaName, provider);
            } catch (NoSuchAlgorithmException nsa) { // try to fallback if possible

                if (specifiedProvider == null && attempted == null) { // default provider doesn't support the alg name,
                    // and we haven't tried BC yet, so try that now:
                    Provider fallback = findBouncyCastle();
                    if (fallback != null) { // BC found, try again:
                        try {
                            T value = doGet(jcaName, fallback);
                            // record the successful attempt so we don't have to do this again:
                            FALLBACK_ATTEMPTS.putIfAbsent(jcaName, Boolean.TRUE);
                            return value;
                        } catch (Throwable ignored) {
                            // record the failed attempt so we don't keep trying and propagate original exception:
                            FALLBACK_ATTEMPTS.putIfAbsent(jcaName, Boolean.FALSE);
                        }
                    }
                }
                // otherwise, we tried the fallback, or there isn't a fallback, so no need to try again, so
                // propagate the exception:
                throw wrap(nsa, jcaName, specifiedProvider, null);
            } catch (Exception e) {
                throw wrap(e, jcaName, specifiedProvider, null);
            }
        }

        protected abstract T doGet(String jcaName, Provider provider) throws Exception;

        // visible for testing:
        protected Exception wrap(Exception e, String jcaName, Provider specifiedProvider, Provider fallbackProvider) {
            String msg = "Unable to obtain '" + jcaName + "' " + getId() + " instance from ";
            if (specifiedProvider != null) {
                msg += "specified '" + specifiedProvider + "' Provider";
            } else {
                msg += "default JCA Provider";
            }
            if (fallbackProvider != null) {
                msg += " or fallback '" + fallbackProvider + "' Provider";
            }
            msg += ": " + e.getMessage();
            return wrap(msg, e);
        }

        protected Exception wrap(String msg, Exception cause) {
            if (Signature.class.isAssignableFrom(clazz) || Mac.class.isAssignableFrom(clazz)) {
                return new SignatureException(msg, cause);
            }
            return new SecurityException(msg, cause);
        }
    }

    private static class CipherFactory extends JcaInstanceFactory<Cipher> {
        CipherFactory() {
            super(Cipher.class);
        }

        @Override
        public Cipher doGet(String jcaName, Provider provider) throws NoSuchPaddingException, NoSuchAlgorithmException {
            return provider != null ? Cipher.getInstance(jcaName, provider) : Cipher.getInstance(jcaName);
        }
    }

    private static class KeyFactoryFactory extends JcaInstanceFactory<KeyFactory> {
        KeyFactoryFactory() {
            super(KeyFactory.class);
        }

        @Override
        public KeyFactory doGet(String jcaName, Provider provider) throws NoSuchAlgorithmException {
            return provider != null ? KeyFactory.getInstance(jcaName, provider) : KeyFactory.getInstance(jcaName);
        }
    }

    private static class SecretKeyFactoryFactory extends JcaInstanceFactory<SecretKeyFactory> {
        SecretKeyFactoryFactory() {
            super(SecretKeyFactory.class);
        }

        @Override
        public SecretKeyFactory doGet(String jcaName, Provider provider) throws NoSuchAlgorithmException {
            return provider != null ? SecretKeyFactory.getInstance(jcaName, provider) : SecretKeyFactory.getInstance(jcaName);
        }
    }

    private static class KeyGeneratorFactory extends JcaInstanceFactory<KeyGenerator> {
        KeyGeneratorFactory() {
            super(KeyGenerator.class);
        }

        @Override
        public KeyGenerator doGet(String jcaName, Provider provider) throws NoSuchAlgorithmException {
            return provider != null ? KeyGenerator.getInstance(jcaName, provider) : KeyGenerator.getInstance(jcaName);
        }
    }

    private static class KeyPairGeneratorFactory extends JcaInstanceFactory<KeyPairGenerator> {
        KeyPairGeneratorFactory() {
            super(KeyPairGenerator.class);
        }

        @Override
        public KeyPairGenerator doGet(String jcaName, Provider provider) throws NoSuchAlgorithmException {
            return provider != null ? KeyPairGenerator.getInstance(jcaName, provider) : KeyPairGenerator.getInstance(jcaName);
        }
    }

    private static class KeyAgreementFactory extends JcaInstanceFactory<KeyAgreement> {
        KeyAgreementFactory() {
            super(KeyAgreement.class);
        }

        @Override
        public KeyAgreement doGet(String jcaName, Provider provider) throws NoSuchAlgorithmException {
            return provider != null ? KeyAgreement.getInstance(jcaName, provider) : KeyAgreement.getInstance(jcaName);
        }
    }

    private static class MessageDigestFactory extends JcaInstanceFactory<MessageDigest> {
        MessageDigestFactory() {
            super(MessageDigest.class);
        }

        @Override
        public MessageDigest doGet(String jcaName, Provider provider) throws NoSuchAlgorithmException {
            return provider != null ? MessageDigest.getInstance(jcaName, provider) : MessageDigest.getInstance(jcaName);
        }
    }

    private static class SignatureFactory extends JcaInstanceFactory<Signature> {
        SignatureFactory() {
            super(Signature.class);
        }

        @Override
        public Signature doGet(String jcaName, Provider provider) throws NoSuchAlgorithmException {
            return provider != null ? Signature.getInstance(jcaName, provider) : Signature.getInstance(jcaName);
        }
    }

    private static class MacFactory extends JcaInstanceFactory<Mac> {
        MacFactory() {
            super(Mac.class);
        }

        @Override
        public Mac doGet(String jcaName, Provider provider) throws NoSuchAlgorithmException {
            return provider != null ? Mac.getInstance(jcaName, provider) : Mac.getInstance(jcaName);
        }
    }

    private static class AlgorithmParametersFactory extends JcaInstanceFactory<AlgorithmParameters> {
        AlgorithmParametersFactory() {
            super(AlgorithmParameters.class);
        }

        @Override
        protected AlgorithmParameters doGet(String jcaName, Provider provider) throws Exception {
            return provider != null ?
                    AlgorithmParameters.getInstance(jcaName, provider) :
                    AlgorithmParameters.getInstance(jcaName);
        }
    }

    private static class CertificateFactoryFactory extends JcaInstanceFactory<CertificateFactory> {
        CertificateFactoryFactory() {
            super(CertificateFactory.class);
        }

        @Override
        protected CertificateFactory doGet(String jcaName, Provider provider) throws Exception {
            return provider != null ?
                    CertificateFactory.getInstance(jcaName, provider) :
                    CertificateFactory.getInstance(jcaName);
        }
    }
}
