package io.jsonwebtoken.impl.io

class FakeServiceDescriptorClassLoader extends ClassLoader {
    private String serviceDescriptor

    FakeServiceDescriptorClassLoader(ClassLoader parent, String serviceDescriptor) {
        super(parent)
        this.serviceDescriptor = serviceDescriptor
    }

    @Override
    Enumeration<URL> getResources(String name) throws IOException {
        if (name.startsWith("META-INF/services/")) {
            return super.getResources(serviceDescriptor)
        } else {
            return super.getResources(name)
        }
    }
}