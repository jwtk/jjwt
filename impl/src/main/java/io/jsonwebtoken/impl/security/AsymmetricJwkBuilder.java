package io.jsonwebtoken.impl.security;

import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.lang.Collections;
import io.jsonwebtoken.security.AsymmetricJwkMutator;
import io.jsonwebtoken.security.MalformedKeyException;

import java.net.URI;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.List;

public abstract class AsymmetricJwkBuilder<K extends Key, J extends AbstractAsymmetricJwk<?, K>, T extends AsymmetricJwkBuilder<K, J, T>> extends DefaultJwkBuilder<K, J, T> implements AsymmetricJwkMutator<T> {

    protected String use;
    protected List<X509Certificate> x509CertificateChain;
    @SuppressWarnings("unused") //used via reflection via SetterFunction in parent class
    protected URI x509Url;
    @SuppressWarnings("unused") //used via reflection via SetterFunction in parent class
    protected byte[] x509Sha1Thumbprint;
    @SuppressWarnings("unused") //used via reflection via SetterFunction in parent class
    protected byte[] x509Sha256Thumbprint;
    protected boolean computeX509Sha1Thumbprint;
    /**
     * Boolean object indicates 3 states: 1) not configured 2) configured as true, 3) configured as false
     */
    protected Boolean computeX509Sha256Thumbprint = null;
    protected Boolean applyX509KeyUse = null;
    private KeyUseStrategy keyUseStrategy = DefaultKeyUseStrategy.INSTANCE;

    public AsymmetricJwkBuilder() {
        super();
    }

    public AsymmetricJwkBuilder(K key) {
        super(key);
    }

    @Override
    public T setPublicKeyUse(String use) {
        return put(DefaultJwk.USE, use);
    }

    public T setUseStrategy(KeyUseStrategy strategy) {
        this.keyUseStrategy = Assert.notNull(strategy, "KeyUseStrategy cannot be null.");
        return tthis();
    }

    @Override
    public T setX509CertificateChain(List<X509Certificate> chain) {
        return put(DefaultJwk.X509_CERT_CHAIN, chain);
    }

    @Override
    public T setX509Url(URI url) {
        return put(DefaultJwk.X509_URL, url);
    }

    @Override
    public T withX509KeyUse(boolean enable) {
        this.applyX509KeyUse = enable;
        return tthis();
    }

    @Override
    public T withX509Sha1Thumbprint(boolean enable) {
        this.computeX509Sha1Thumbprint = enable;
        return tthis();
    }

    @Override
    public T withX509Sha256Thumbprint(boolean enable) {
        this.computeX509Sha256Thumbprint = enable;
        return tthis();
    }

    private byte[] computeThumbprint(final X509Certificate cert, final String jcaName) {
        try {
            byte[] encoded = cert.getEncoded();
            MessageDigest digest = MessageDigest.getInstance(jcaName);
            return digest.digest(encoded);
        } catch (CertificateEncodingException e) {
            String msg = "Unable to access X509Certificate encoded bytes necessary to compute a " + jcaName +
                " thumbprint. Certificate: {" + cert + "}.  Cause: " + e.getMessage();
            throw new MalformedKeyException(msg, e);
        } catch (NoSuchAlgorithmException e) {
            String msg = "JCA Algorithm Name '" + jcaName + "' is not available: " + e.getMessage();
            throw new IllegalStateException(msg, e);
        }
    }

    @Override
    protected J createJwk() {
        X509Certificate firstCert = null;
        if (!Collections.isEmpty(this.x509CertificateChain)) {
            firstCert = this.x509CertificateChain.get(0);
        }

        if (applyX509KeyUse == null) { //if not specified, enable by default if possible:
            applyX509KeyUse = firstCert != null;
        }
        if (computeX509Sha256Thumbprint == null) { //if not specified, enable by default if possible:
            computeX509Sha256Thumbprint = firstCert != null;
        }

        if (firstCert != null) {
            if (applyX509KeyUse) {
                KeyUsage usage = new KeyUsage(firstCert);
                String use = keyUseStrategy.toJwkValue(usage);
                if (use != null) {
                    setPublicKeyUse(use);
                }
            }
            if (computeX509Sha1Thumbprint) {
                byte[] thumbprint = computeThumbprint(firstCert, "SHA-1");
                put(DefaultJwk.X509_SHA1_THUMBPRINT, thumbprint);
            }
            if (computeX509Sha256Thumbprint) {
                byte[] thumbprint = computeThumbprint(firstCert, "SHA-256");
                put(DefaultJwk.X509_SHA256_THUMBPRINT, thumbprint);
            }
        }
        return super.createJwk();
    }
}
