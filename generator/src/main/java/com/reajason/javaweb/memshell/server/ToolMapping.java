package com.reajason.javaweb.memshell.server;

import lombok.Builder;
import lombok.Singular;
import org.apache.commons.lang3.tuple.Pair;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * @author ReaJason
 * @since 2025/2/21
 */
@Builder
public class ToolMapping {

    @Singular("addShellClass")
    private final Map<String, Class<?>> shellClassMap;

    public List<String> getSupportedShellTypes() {
        return new ArrayList<>(shellClassMap.keySet());
    }

    public Map<String, Pair<Class<?>, Class<?>>> getShellClassMap(InjectorMapping injectorMapping) {
        Map<String, Pair<Class<?>, Class<?>>> result = new LinkedHashMap<>();
        for (String type : injectorMapping.getSupportedShellTypes()) {
            Class<?> shellClass = shellClassMap.get(type);
            Class<?> injectorClass = injectorMapping.getInjector(type);
            if (shellClass != null && injectorClass != null) {
                result.put(type, Pair.of(shellClass, injectorClass));
            }
        }
        return result;
    }
}
