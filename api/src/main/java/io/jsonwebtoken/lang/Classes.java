/*
 * Copyright (C) 2014 jsonwebtoken.io
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.jsonwebtoken.lang;

import java.io.InputStream;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.URL;

/**
 * Utility methods for working with {@link Class}es.
 *
 * @since 0.1
 */
public final class Classes {

    private Classes() {
    } //prevent instantiation

    private static final ClassLoaderAccessor THREAD_CL_ACCESSOR = new ExceptionIgnoringAccessor() {
        @Override
        protected ClassLoader doGetClassLoader() {
            return Thread.currentThread().getContextClassLoader();
        }
    };

    private static final ClassLoaderAccessor CLASS_CL_ACCESSOR = new ExceptionIgnoringAccessor() {
        @Override
        protected ClassLoader doGetClassLoader() {
            return Classes.class.getClassLoader();
        }
    };

    private static final ClassLoaderAccessor SYSTEM_CL_ACCESSOR = new ExceptionIgnoringAccessor() {
        @Override
        protected ClassLoader doGetClassLoader() {
            return ClassLoader.getSystemClassLoader();
        }
    };

    /**
     * Attempts to load the specified class name from the current thread's
     * {@link Thread#getContextClassLoader() context class loader}, then the
     * current ClassLoader (<code>Classes.class.getClassLoader()</code>), then the system/application
     * ClassLoader (<code>ClassLoader.getSystemClassLoader()</code>, in that order.  If any of them cannot locate
     * the specified class, an <code>UnknownClassException</code> is thrown (our RuntimeException equivalent of
     * the JRE's <code>ClassNotFoundException</code>.
     *
     * @param fqcn the fully qualified class name to load
     * @param <T>  The type of Class returned
     * @return the located class
     * @throws UnknownClassException if the class cannot be found.
     */
    @SuppressWarnings("unchecked")
    public static <T> Class<T> forName(String fqcn) throws UnknownClassException {

        Class<?> clazz = THREAD_CL_ACCESSOR.loadClass(fqcn);

        if (clazz == null) {
            clazz = CLASS_CL_ACCESSOR.loadClass(fqcn);
        }

        if (clazz == null) {
            clazz = SYSTEM_CL_ACCESSOR.loadClass(fqcn);
        }

        if (clazz == null) {
            String msg = "Unable to load class named [" + fqcn + "] from the thread context, current, or " +
                    "system/application ClassLoaders.  All heuristics have been exhausted.  Class could not be found.";

            if (fqcn != null && fqcn.startsWith("io.jsonwebtoken.impl")) {
                msg += "  Have you remembered to include the jjwt-impl.jar in your runtime classpath?";
            }

            throw new UnknownClassException(msg);
        }

        return (Class<T>) clazz;
    }

    /**
     * Returns the specified resource by checking the current thread's
     * {@link Thread#getContextClassLoader() context class loader}, then the
     * current ClassLoader (<code>Classes.class.getClassLoader()</code>), then the system/application
     * ClassLoader (<code>ClassLoader.getSystemClassLoader()</code>, in that order, using
     * {@link ClassLoader#getResourceAsStream(String) getResourceAsStream(name)}.
     *
     * @param name the name of the resource to acquire from the classloader(s).
     * @return the InputStream of the resource found, or <code>null</code> if the resource cannot be found from any
     * of the three mentioned ClassLoaders.
     * @since 0.8
     */
    public static InputStream getResourceAsStream(String name) {

        InputStream is = THREAD_CL_ACCESSOR.getResourceStream(name);

        if (is == null) {
            is = CLASS_CL_ACCESSOR.getResourceStream(name);
        }

        if (is == null) {
            is = SYSTEM_CL_ACCESSOR.getResourceStream(name);
        }

        return is;
    }

    /**
     * Returns the specified resource URL by checking the current thread's
     * {@link Thread#getContextClassLoader() context class loader}, then the
     * current ClassLoader (<code>Classes.class.getClassLoader()</code>), then the system/application
     * ClassLoader (<code>ClassLoader.getSystemClassLoader()</code>, in that order, using
     * {@link ClassLoader#getResource(String) getResource(name)}.
     *
     * @param name the name of the resource to acquire from the classloader(s).
     * @return the URL of the resource found, or <code>null</code> if the resource cannot be found from any
     * of the three mentioned ClassLoaders.
     * @since JJWT_RELEASE_VERSION
     */
    private static URL getResource(String name) {
        URL url = THREAD_CL_ACCESSOR.getResource(name);
        if (url == null) {
            url = CLASS_CL_ACCESSOR.getResource(name);
        }
        if (url == null) {
            return SYSTEM_CL_ACCESSOR.getResource(name);
        }
        return url;
    }

    /**
     * Returns {@code true} if the specified {@code fullyQualifiedClassName} can be found in any of the thread
     * context, class, or system classloaders, or {@code false} otherwise.
     *
     * @param fullyQualifiedClassName the fully qualified class name to check
     * @return {@code true} if the specified {@code fullyQualifiedClassName} can be found in any of the thread
     * context, class, or system classloaders, or {@code false} otherwise.
     */
    public static boolean isAvailable(String fullyQualifiedClassName) {
        try {
            forName(fullyQualifiedClassName);
            return true;
        } catch (UnknownClassException e) {
            return false;
        }
    }

    /**
     * Creates and returns a new instance of the class with the specified fully qualified class name using the
     * classes default no-argument constructor.
     *
     * @param fqcn the fully qualified class name
     * @param <T>  the type of object created
     * @return a new instance of the specified class name
     */
    @SuppressWarnings("unchecked")
    public static <T> T newInstance(String fqcn) {
        return (T) newInstance(forName(fqcn));
    }

    /**
     * Creates and returns a new instance of the specified fully qualified class name using the
     * specified {@code args} arguments provided to the constructor with {@code ctorArgTypes}
     *
     * @param fqcn         the fully qualified class name
     * @param ctorArgTypes the argument types of the constructor to invoke
     * @param args         the arguments to supply when invoking the constructor
     * @param <T>          the type of object created
     * @return the newly created object
     */
    public static <T> T newInstance(String fqcn, Class<?>[] ctorArgTypes, Object... args) {
        Class<T> clazz = forName(fqcn);
        Constructor<T> ctor = getConstructor(clazz, ctorArgTypes);
        return instantiate(ctor, args);
    }

    /**
     * Creates and returns a new instance of the specified fully qualified class name using a constructor that matches
     * the specified {@code args} arguments.
     *
     * @param fqcn fully qualified class name
     * @param args the arguments to supply to the constructor
     * @param <T>  the type of the object created
     * @return the newly created object
     */
    @SuppressWarnings("unchecked")
    public static <T> T newInstance(String fqcn, Object... args) {
        return (T) newInstance(forName(fqcn), args);
    }

    /**
     * Creates a new instance of the specified {@code clazz} via {@code clazz.newInstance()}.
     *
     * @param clazz the class to invoke
     * @param <T>   the type of the object created
     * @return the newly created object
     */
    public static <T> T newInstance(Class<T> clazz) {
        if (clazz == null) {
            String msg = "Class method parameter cannot be null.";
            throw new IllegalArgumentException(msg);
        }
        try {
            return clazz.newInstance();
        } catch (Exception e) {
            throw new InstantiationException("Unable to instantiate class [" + clazz.getName() + "]", e);
        }
    }

    /**
     * Returns a new instance of the specified {@code clazz}, invoking the associated constructor with the specified
     * {@code args} arguments.
     *
     * @param clazz the class to invoke
     * @param args  the arguments matching an associated class constructor
     * @param <T>   the type of the created object
     * @return the newly created object
     */
    public static <T> T newInstance(Class<T> clazz, Object... args) {
        Class<?>[] argTypes = new Class[args.length];
        for (int i = 0; i < args.length; i++) {
            argTypes[i] = args[i].getClass();
        }
        Constructor<T> ctor = getConstructor(clazz, argTypes);
        return instantiate(ctor, args);
    }

    /**
     * Returns the {@link Constructor} for the specified {@code Class} with arguments matching the specified
     * {@code argTypes}.
     *
     * @param clazz    the class to inspect
     * @param argTypes the argument types for the desired constructor
     * @param <T>      the type of object to create
     * @return the constructor matching the specified argument types
     * @throws IllegalStateException if the constructor for the specified {@code argTypes} does not exist.
     */
    public static <T> Constructor<T> getConstructor(Class<T> clazz, Class<?>... argTypes) throws IllegalStateException {
        try {
            return clazz.getConstructor(argTypes);
        } catch (NoSuchMethodException e) {
            throw new IllegalStateException(e);
        }

    }

    /**
     * Creates a new object using the specified {@link Constructor}, invoking it with the specified constructor
     * {@code args} arguments.
     *
     * @param ctor the constructor to invoke
     * @param args the arguments to supply to the constructor
     * @param <T>  the type of object to create
     * @return the new object instance
     * @throws InstantiationException if the constructor cannot be invoked successfully
     */
    public static <T> T instantiate(Constructor<T> ctor, Object... args) {
        try {
            return ctor.newInstance(args);
        } catch (Exception e) {
            String msg = "Unable to instantiate instance with constructor [" + ctor + "]";
            throw new InstantiationException(msg, e);
        }
    }

    /**
     * Invokes the fully qualified class name's method named {@code methodName} with parameters of type {@code argTypes}
     * using the {@code args} as the method arguments.
     *
     * @param fqcn       fully qualified class name to locate
     * @param methodName name of the method to invoke on the class
     * @param argTypes   the method argument types supported by the {@code methodName} method
     * @param args       the runtime arguments to use when invoking the located class method
     * @param <T>        the expected type of the object returned from the invoked method.
     * @return the result returned by the invoked method
     * @since 0.10.0
     */
    public static <T> T invokeStatic(String fqcn, String methodName, Class<?>[] argTypes, Object... args) {
        try {
            Class<?> clazz = Classes.forName(fqcn);
            return invokeStatic(clazz, methodName, argTypes, args);
        } catch (Exception e) {
            String msg = "Unable to invoke class method " + fqcn + "#" + methodName + ".  Ensure the necessary " +
                    "implementation is in the runtime classpath.";
            throw new IllegalStateException(msg, e);
        }
    }

    /**
     * Invokes the {@code clazz}'s matching static method (named {@code methodName} with exact argument types
     * of {@code argTypes}) with the given {@code args} arguments, and returns the method return value.
     *
     * @param clazz      the class to invoke
     * @param methodName the name of the static method on {@code clazz} to invoke
     * @param argTypes   the types of the arguments accepted by the method
     * @param args       the actual runtime arguments to use when invoking the method
     * @param <T>        the type of object expected to be returned from the method
     * @return the result returned by the invoked method.
     * @since JJWT_RELEASE_VERSION
     */
    @SuppressWarnings("unchecked")
    public static <T> T invokeStatic(Class<?> clazz, String methodName, Class<?>[] argTypes, Object... args) {
        try {
            Method method = clazz.getDeclaredMethod(methodName, argTypes);
            method.setAccessible(true);
            return (T) method.invoke(null, args);
        } catch (NoSuchMethodException | InvocationTargetException | IllegalAccessException e) {
            Throwable cause = e.getCause();
            if (cause instanceof RuntimeException) {
                throw ((RuntimeException) cause); //propagate
            }
            String msg = "Unable to invoke class method " + clazz.getName() + "#" + methodName +
                    ". Ensure the necessary implementation is in the runtime classpath.";
            throw new IllegalStateException(msg, e);
        }
    }

    /**
     * @since 1.0
     */
    private interface ClassLoaderAccessor {
        Class<?> loadClass(String fqcn);

        URL getResource(String name);

        InputStream getResourceStream(String name);
    }

    /**
     * @since 1.0
     */
    private static abstract class ExceptionIgnoringAccessor implements ClassLoaderAccessor {

        public Class<?> loadClass(String fqcn) {
            Class<?> clazz = null;
            ClassLoader cl = getClassLoader();
            if (cl != null) {
                try {
                    clazz = cl.loadClass(fqcn);
                } catch (ClassNotFoundException e) {
                    //Class couldn't be found by loader
                }
            }
            return clazz;
        }

        @Override
        public URL getResource(String name) {
            URL url = null;
            ClassLoader cl = getClassLoader();
            if (cl != null) {
                url = cl.getResource(name);
            }
            return url;
        }

        public InputStream getResourceStream(String name) {
            InputStream is = null;
            ClassLoader cl = getClassLoader();
            if (cl != null) {
                is = cl.getResourceAsStream(name);
            }
            return is;
        }

        protected final ClassLoader getClassLoader() {
            try {
                return doGetClassLoader();
            } catch (Throwable t) {
                //Unable to get ClassLoader
            }
            return null;
        }

        protected abstract ClassLoader doGetClassLoader() throws Throwable;
    }
}

