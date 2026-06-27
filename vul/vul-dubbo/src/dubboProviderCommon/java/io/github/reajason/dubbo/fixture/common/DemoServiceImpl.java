package io.github.reajason.dubbo.fixture.common;

import io.github.reajason.dubbo.fixture.api.DemoService;

public class DemoServiceImpl implements DemoService {

    private final String providerName;

    public DemoServiceImpl(String providerName) {
        this.providerName = providerName;
    }

    @Override
    public String sayHello(String name) {
        return "Hello, " + name + " from " + providerName;
    }
}
