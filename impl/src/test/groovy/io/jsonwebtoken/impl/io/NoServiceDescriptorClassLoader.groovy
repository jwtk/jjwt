package io.jsonwebtoken.impl.io

class NoServiceDescriptorClassLoader extends ClassLoader {
    NoServiceDescriptorClassLoader(ClassLoader parent) {
        super(parent)
    }

    @Override
    Enumeration<URL> getResources(String name) throws IOException {
        if (name.startsWith("META-INF/services/")) {
            return Collections.emptyEnumeration()
        } else {
            return super.getResources(name)
        }
    }
}