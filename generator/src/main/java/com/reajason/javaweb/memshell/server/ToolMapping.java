package com.reajason.javaweb.memshell.server;

import lombok.Builder;
import lombok.Getter;
import lombok.Singular;
import org.apache.commons.lang3.tuple.Pair;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

/**
 * @author ReaJason
 * @since 2025/2/21
 */
@Builder
@Getter
public class ToolMapping {

    @Singular("addShellClass")
    private final Map<String, Class<?>> shellClassMap;

    public ToolMapping(Map<String, Class<?>> shellClassMap) {
        this.shellClassMap = new LinkedHashMap<>(shellClassMap);
    }

    public Set<String> getSupportedShellTypes() {
        return shellClassMap.keySet();
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
