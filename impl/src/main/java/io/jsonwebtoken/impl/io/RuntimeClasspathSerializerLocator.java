package io.jsonwebtoken.impl.io;

import io.jsonwebtoken.io.Serializer;
import io.jsonwebtoken.lang.Assert;
import io.jsonwebtoken.lang.Classes;

import java.util.concurrent.atomic.AtomicReference;

/**
 * @since 0.10.0
 */
public class RuntimeClasspathSerializerLocator implements InstanceLocator<Serializer> {

    private static final AtomicReference<Serializer<Object>> SERIALIZER = new AtomicReference<>();

    @SuppressWarnings("unchecked")
    @Override
    public Serializer<Object> getInstance() {
        Serializer<Object> serializer = SERIALIZER.get();
        if (serializer == null) {
            serializer = locate();
            Assert.state(serializer != null, "locate() cannot return null.");
            if (!compareAndSet(serializer)) {
                serializer = SERIALIZER.get();
            }
        }
        Assert.state(serializer != null, "serializer cannot be null.");
        return serializer;
    }

    @SuppressWarnings("WeakerAccess") //to allow testing override
    protected Serializer<Object> locate() {
        if (isAvailable("io.jsonwebtoken.io.JacksonSerializer")) {
            return Classes.newInstance("io.jsonwebtoken.io.JacksonSerializer");
        } else if (isAvailable("io.jsonwebtoken.io.OrgJsonSerializer")) {
            return Classes.newInstance("io.jsonwebtoken.io.OrgJsonSerializer");
        } else {
            throw new IllegalStateException("Unable to discover any JSON Serializer implementations on the classpath.");
        }
    }

    @SuppressWarnings("WeakerAccess") //to allow testing override
    protected boolean compareAndSet(Serializer<Object> s) {
        return SERIALIZER.compareAndSet(null, s);
    }

    @SuppressWarnings("WeakerAccess") //to allow testing override
    protected boolean isAvailable(String fqcn) {
        return Classes.isAvailable(fqcn);
    }
}
