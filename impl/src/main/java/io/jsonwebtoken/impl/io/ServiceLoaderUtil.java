package io.jsonwebtoken.impl.io;

import java.util.Iterator;
import java.util.ServiceConfigurationError;
import java.util.ServiceLoader;

final class ServiceLoaderUtil {

    static <T> T loadFromService(Class<T> serviceClass) {
            String errorMessage = "ServiceLoader failed to find implementation for class: '%s', you are likely missing" +
                    "a dependency such as 'io.jsonwebtoken:jjwt-jackson', see https://github.com/jwtk/jjwt#json-support";
        try {
            ServiceLoader<T> serviceLoader = ServiceLoader.load(serviceClass);

            Iterator<T> iter = serviceLoader.iterator();
            if (iter.hasNext()) {
                return iter.next();
            }
        } catch(ServiceConfigurationError e) {
            throw new IllegalStateException(String.format(errorMessage, serviceClass.getName()), e);
        }
        throw new IllegalStateException(String.format(errorMessage, serviceClass.getName()));
    }
}
