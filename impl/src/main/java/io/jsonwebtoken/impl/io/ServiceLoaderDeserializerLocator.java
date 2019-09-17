package io.jsonwebtoken.impl.io;

import io.jsonwebtoken.io.Deserializer;

/**
 * @since 0.11.0
 */
public class ServiceLoaderDeserializerLocator implements InstanceLocator<Deserializer> {

    @Override
    public Deserializer getInstance() {
        return Holder.serializer;
    }

    private static class Holder {
        private static final Deserializer serializer = ServiceLoaderUtil.loadFromService(Deserializer.class);
    }
}
