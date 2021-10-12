package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.impl.lang.CheckedFunction;
import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.lang.Classes;
import io.jsonwebtoken.security.SecurityException;
import io.jsonwebtoken.security.SignatureException;

import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Signature;

public class JcaTemplate {

    private final String jcaName;
    private final Provider provider;
    private final SecureRandom secureRandom;

    JcaTemplate(String jcaName, Provider provider) {
        this(jcaName, provider, Randoms.secureRandom());
    }

    JcaTemplate(String jcaName, Provider provider, SecureRandom secureRandom) {
        Assert.hasText(jcaName, "jcaName string cannot be null or empty.");
        this.jcaName = jcaName;
        this.provider = provider;
        this.secureRandom = Assert.notNull(secureRandom, "SecureRandom cannot be null.");
    }

    public <T, R> R execute(Class<T> clazz, CheckedFunction<T, R> fn) throws SecurityException {
        return execute(new JcaInstanceSupplier<>(clazz, this.jcaName, this.provider), fn);
    }

    public SecretKey generateSecretKey(final int keyBitLength) {
        return execute(KeyGenerator.class, new CheckedFunction<KeyGenerator, SecretKey>() {
            @Override
            public SecretKey apply(KeyGenerator generator) {
                generator.init(keyBitLength, secureRandom);
                return generator.generateKey();
            }
        });
    }

    public KeyPair generateKeyPair(final int keyBitLength) {
        return execute(KeyPairGenerator.class, new CheckedFunction<KeyPairGenerator, KeyPair>() {
            @Override
            public KeyPair apply(KeyPairGenerator generator) {
                generator.initialize(keyBitLength, secureRandom);
                return generator.generateKeyPair();
            }
        });
    }

    private <T, R> R execute(JcaInstanceSupplier<T> supplier, CheckedFunction<T, R> callback) throws SecurityException {
        try {
            T instance = supplier.getInstance();
            return callback.apply(instance);
        } catch (SecurityException se) {
            throw se; //propagate
        } catch (Exception e) {
            throw new SecurityException(supplier.getName() + " callback execution failed: " + e.getMessage(), e);
        }
    }

    private interface InstanceSupplier<T> {
        T getInstance() throws Exception;
    }

    //visible for testing
    static class JcaInstanceSupplier<T> implements InstanceSupplier<T> {

        private static final String METHOD_NAME = "getInstance";
        private static final Class<?>[] PROVIDER_ARGS = new Class[]{String.class, Provider.class};
        private static final Class<?>[] NAME_ARGS = new Class[]{String.class};

        private final Class<T> clazz;
        private final String name;
        private final String jcaName;
        private final Provider provider;

        JcaInstanceSupplier(Class<T> clazz, String jcaName, Provider provider) {
            this.clazz = Assert.notNull(clazz, "Clazz cannot be null.");
            this.name = clazz.getSimpleName();
            this.jcaName = jcaName;
            Assert.hasText(jcaName, "jcaName cannot be null or empty.");
            this.provider = provider;
        }

        public String getName() {
            return name;
        }

        @Override
        public final T getInstance() throws Exception {
            try {
                return doGetInstance();
            } catch (Exception e) {
                String msg = "Unable to obtain " + this.name + " instance from ";
                if (this.provider != null) {
                    msg += "specified Provider {" + this.provider + "} ";
                } else {
                    msg += "default JCA Provider ";
                }
                msg += "for JCA algorithm '" + this.jcaName + "': " + e.getMessage();
                throw wrap(msg, e);
            }
        }

        protected Exception wrap(String msg, Exception cause) {
            if (cause instanceof SecurityException) {
                return cause;
            }
            if (Signature.class.isAssignableFrom(clazz) || Mac.class.isAssignableFrom(clazz)) {
                return new SignatureException(msg, cause);
            }
            return new SecurityException(msg, cause);
        }

        protected T doGetInstance() {
            return provider != null ?
                Classes.<T>invokeStatic(clazz, METHOD_NAME, PROVIDER_ARGS, jcaName, provider) :
                Classes.<T>invokeStatic(clazz, METHOD_NAME, NAME_ARGS, jcaName);
        }
    }
}
