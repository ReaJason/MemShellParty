package com.reajason.javaweb.memshell.server;

import lombok.Builder;
import lombok.Singular;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

/**
 * @author ReaJason
 * @since 2025/2/21
 */
@Builder
public class InjectorMapping {

    @Singular("addInjector")
    private final Map<String, Class<?>> injectorMap;

    public InjectorMapping(Map<String, Class<?>> injectorMap) {
        this.injectorMap = new LinkedHashMap<>(injectorMap);
    }

    public Class<?> getInjector(String type) {
        return injectorMap.get(type);
    }

    public Set<String> getSupportedShellTypes() {
        return Collections.unmodifiableSet(injectorMap.keySet());
    }
}