package io.github.reajason.javaweb.proxy;

@FunctionalInterface
public interface DubboHandler {

    byte[] handle(byte[] request) throws Exception;
}
