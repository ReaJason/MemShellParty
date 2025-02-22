package com.reajason.javaweb.memshell.server;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Singular;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * @author ReaJason
 * @since 2025/2/21
 */
@Builder
@AllArgsConstructor
public class InjectorMapping {

    @Singular("addInjector")
    private final Map<String, Class<?>> injectorMap;

    public Class<?> getInjector(String type) {
        return injectorMap.get(type);
    }

    public List<String> getSupportedShellTypes() {
        return new ArrayList<>(injectorMap.keySet());
    }
}