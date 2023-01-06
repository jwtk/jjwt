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
import io.jsonwebtoken.impl.lang.CheckedFunction;
import io.jsonwebtoken.impl.lang.DefaultRegistry;
import io.jsonwebtoken.impl.lang.Function;
import io.jsonwebtoken.impl.lang.Registry;
import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.lang.Collections;
import io.jsonwebtoken.security.SecurityException;
import io.jsonwebtoken.security.SignatureException;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.AlgorithmParameterSpec;
import java.util.List;

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
            new AlgorithmParametersFactory()
    );

    private static final Registry<Class<?>, InstanceFactory<?>> REGISTRY = new DefaultRegistry<>(FACTORIES,
            new Function<InstanceFactory<?>, Class<?>>() {
                @Override
                public Class<?> apply(InstanceFactory<?> factory) {
                    return factory.getInstanceClass();
                }
            });

    private final String jcaName;
    private final Provider provider;
    private final SecureRandom secureRandom;

    JcaTemplate(String jcaName, Provider provider) {
        this(jcaName, provider, null);
    }

    JcaTemplate(String jcaName, Provider provider, SecureRandom secureRandom) {
        this.jcaName = Assert.hasText(jcaName, "jcaName string cannot be null or empty.");
        this.secureRandom = secureRandom != null ? secureRandom : Randoms.secureRandom();
        this.provider = provider; //may be null, meaning to use the JCA subsystem default provider
    }

    private <T, R> R execute(Class<T> clazz, CheckedFunction<T, R> fn) throws SecurityException {
        InstanceFactory<?> factory = REGISTRY.apply(clazz);
        Assert.notNull(factory, "Unsupported JCA instance class.");
        return execute(factory, clazz, fn);
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

    // protected visibility for testing
    private <T, R> R execute(InstanceFactory<?> factory, Class<T> clazz, CheckedFunction<T, R> callback) throws SecurityException {
        try {
            Object object = factory.get(this.jcaName, this.provider);
            T instance = Assert.isInstanceOf(clazz, object, "Factory instance does not match expected type.");
            return callback.apply(instance);
        } catch (SecurityException se) {
            throw se; //propagate
        } catch (Exception e) {
            throw new SecurityException(factory.getId() + " callback execution failed: " + e.getMessage(), e);
        }
    }

    private interface InstanceFactory<T> extends Identifiable {

        Class<T> getInstanceClass();

        T get(String jcaName, Provider provider) throws Exception;
    }

    private static abstract class JcaInstanceFactory<T> implements InstanceFactory<T> {

        private final Class<T> clazz;

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

        @Override
        public final T get(String jcaName, Provider provider) throws Exception {
            Assert.hasText(jcaName, "jcaName cannot be null or empty.");
            try {
                return doGet(jcaName, provider);
            } catch (Exception e) {
                String msg = "Unable to obtain " + getId() + " instance from ";
                if (provider != null) {
                    msg += "specified Provider '" + provider + "' ";
                } else {
                    msg += "default JCA Provider ";
                }
                msg += "for JCA algorithm '" + jcaName + "': " + e.getMessage();
                throw wrap(msg, e);
            }
        }

        protected abstract T doGet(String jcaName, Provider provider) throws Exception;

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
}
