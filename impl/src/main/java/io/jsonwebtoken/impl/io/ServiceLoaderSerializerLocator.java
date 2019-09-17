package io.jsonwebtoken.impl.io;

import io.jsonwebtoken.io.Serializer;

/**
 * @since 0.11.0
 */
public class ServiceLoaderSerializerLocator implements InstanceLocator<Serializer> {

    @Override
    public Serializer getInstance() {
        return Holder.serializer;
    }

    private static class Holder {
        private static final Serializer serializer = ServiceLoaderUtil.loadFromService(Serializer.class);
    }
}
