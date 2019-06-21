package io.jsonwebtoken.lang;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.ServiceLoader;

public final class Services {

    public static <T> List<T> loadAllAvailableImplementations(Class<T> clazz) {
        ServiceLoader<T> serviceLoader = ServiceLoader.load(clazz);

        List<T> implementations = new ArrayList<>();
        for (T implementation : serviceLoader) {
            implementations.add(implementation);
        }

        return Collections.unmodifiableList(implementations);
    }
}
