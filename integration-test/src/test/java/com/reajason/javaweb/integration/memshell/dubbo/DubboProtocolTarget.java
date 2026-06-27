package com.reajason.javaweb.integration.memshell.dubbo;

final class DubboProtocolTarget {
    private final String protocol;
    private final int port;

    DubboProtocolTarget(String protocol, int port) {
        this.protocol = protocol;
        this.port = port;
    }

    String protocol() {
        return protocol;
    }

    int port() {
        return port;
    }

    String url(String host, String interfaceName) {
        return protocol + "://" + host + ":" + port + "/" + interfaceName;
    }

    String url(String host, int mappedPort, String interfaceName) {
        return protocol + "://" + host + ":" + mappedPort + "/" + interfaceName;
    }
}
