package io.jsonwebtoken.lang;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.ServiceLoader;

/**
 * Helper class for loading services from the classpath, using a {@link ServiceLoader}. Decouples loading logic for
 * better separation of concerns and testability.
 */
public final class Services {

    /**
     * Loads and instantiates all service implementation of the given SPI class and returns them as a List.
     *
     * @param spi The class of the Service Provider Interface
     * @param <T> The type of the SPI
     * @return An unmodifiable list with an instance of all available implementations of the SPI. No guarantee is given
     * on the order of implementations, if more than one.
     */
    public static <T> List<T> loadAllAvailableImplementations(Class<T> spi) {
        ServiceLoader<T> serviceLoader = ServiceLoader.load(spi);

        List<T> implementations = new ArrayList<>();
        for (T implementation : serviceLoader) {
            implementations.add(implementation);
        }

        return Collections.unmodifiableList(implementations);
    }

    /**
     * Loads the first available implementation the given SPI class from the classpath. Uses the {@link ServiceLoader}
     * to find implementations. When multiple implementations are available it will return the first one that it
     * encounters. There is no guarantee with regard to ordering.
     *
     * @param spi The class of the Service Provider Interface
     * @param <T> The type of the SPI
     * @return A new instance of the service.
     * @throws ImplementationNotFoundException When no implementation the SPI is available on the classpath.
     */
    public static <T> T loadFirst(Class<T> spi) {
        ServiceLoader<T> serviceLoader = ServiceLoader.load(spi);
        if (serviceLoader.iterator().hasNext()) {
            return serviceLoader.iterator().next();
        } else {
            throw new ImplementationNotFoundException("No implementation of " + spi.getName() + " found on the classpath. Make sure to include an implementation of jjwt-api.");
        }
    }
}
