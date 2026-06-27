package io.github.reajason.dubbo.fixture.common;

import io.github.reajason.dubbo.fixture.api.BytecodeLoadingService;

public class BytecodeLoadingServiceImpl implements BytecodeLoadingService {

    @Override
    public String loadBytes(String base64) {
        return BytecodeLoadingSupport.loadBase64(base64);
    }
}
