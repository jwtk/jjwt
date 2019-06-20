package io.jsonwebtoken.factory;

import java.util.ServiceLoader;

/**
 * Helper class for loading a factory implementations from the classpath, using a {@link ServiceLoader}. Decouples
 * loading logic for better separation of concerns and testability.
 */
public final class FactoryLoader {

    private FactoryLoader() {
    }

    /**
     * Loads an available implementation of {@link JwtFactory} from the classpath. Uses the {@link ServiceLoader} to
     * find implementations. When multiple implementations are available it will return the first one that it
     * encounters. There is no guarantee with regard to ordering.
     *
     * @return A new JwtFactory
     * @throws ImplementationNotFoundException When no implementation of {@link JwtFactory} is available as a service
     *                                         implementation on the classpath.
     * @see ServiceLoader#load(Class)
     */
    public static JwtFactory loadFactory() {
        return loadFactory(JwtFactory.class);
    }

    /**
     * Loads an available implementation of {@link CompressionCodecFactory} from the classpath. Uses the {@link
     * ServiceLoader} to find implementations. When multiple implementations are available it will return the first one
     * that it encounters. There is no guarantee with regard to ordering.
     *
     * @return A new CompressionCodecFactory
     * @throws ImplementationNotFoundException When no implementation of {@link CompressionCodecFactory} is available as
     *                                         a service implementation on the classpath.
     * @see ServiceLoader#load(Class)
     */
    public static CompressionCodecFactory loadCompressionCodecFactory() {
        return loadFactory(CompressionCodecFactory.class);
    }

    private static <T> T loadFactory(Class<T> clazz) {
        ServiceLoader<T> serviceLoader = ServiceLoader.load(clazz);
        if (serviceLoader.iterator().hasNext()) {
            return serviceLoader.iterator().next();
        } else {
            throw new ImplementationNotFoundException("No implementation of " + clazz.getName() + " found on the classpath. Make sure to include an implementation of jjwt-api.");
        }
    }
}
