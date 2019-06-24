package io.jsonwebtoken.impl.io;

import io.jsonwebtoken.io.Deserializer;
import io.jsonwebtoken.lang.Assert;

import java.util.Iterator;
import java.util.ServiceLoader;
import java.util.concurrent.atomic.AtomicReference;

/**
 * @since 0.10.0
 */
public class RuntimeClasspathDeserializerLocator<T> implements InstanceLocator<Deserializer<T>> {

    private static final AtomicReference<Deserializer> DESERIALIZER = new AtomicReference<>();

    @SuppressWarnings("unchecked")
    @Override
    public Deserializer<T> getInstance() {
        Deserializer<T> deserializer = DESERIALIZER.get();
        if (deserializer == null) {
            deserializer = locate();
            Assert.state(deserializer != null, "locate() cannot return null.");
            if (!compareAndSet(deserializer)) {
                deserializer = DESERIALIZER.get();
            }
        }
        Assert.state(deserializer != null, "deserializer cannot be null.");
        return deserializer;
    }

    @SuppressWarnings({"unchecked"}) //to allow testing override
    protected Deserializer<T> locate() {
        ServiceLoader<Deserializer> serviceLoader = ServiceLoader.load(Deserializer.class);
        Iterator<Deserializer> iterator = serviceLoader.iterator();
        if(iterator.hasNext()) {
            return  (Deserializer<T>)iterator.next();
        } else {
            throw new IllegalStateException("Unable to discover any JSON Deserializer implementations on the classpath.");
        }
    }

    @SuppressWarnings("WeakerAccess") //to allow testing override
    protected boolean compareAndSet(Deserializer<T> d) {
        return DESERIALIZER.compareAndSet(null, d);
    }
}
