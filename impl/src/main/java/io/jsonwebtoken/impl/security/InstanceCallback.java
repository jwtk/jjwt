package io.jsonwebtoken.impl.security;

public interface InstanceCallback<I,O> {

    O doWithInstance(I instance) throws Exception;
}
