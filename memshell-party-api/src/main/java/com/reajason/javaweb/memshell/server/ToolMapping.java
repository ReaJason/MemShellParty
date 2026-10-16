package com.reajason.javaweb.memshell.server;

import lombok.Builder;
import lombok.Getter;
import lombok.Singular;
import com.reajason.javaweb.utils.tuple.Pair;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

/**
 * Maps shell types to shell template class names.
 *
 * <p>Templates are referenced by binary name, never as {@link Class} literals: loading a
 * template class would drag its supertypes (servlet, spring, dubbo APIs) onto the
 * consumer's classpath. Generation resolves templates as bytes via the class loader.
 *
 * @author ReaJason
 * @since 2025/2/21
 */
@Builder
@Getter
public class ToolMapping {

    /**
     * shellType -&gt; shell template class binary name
     */
    @Singular("addShellClass")
    private final Map<String, String> shellClassMap;

    public ToolMapping(Map<String, String> shellClassMap) {
        this.shellClassMap = new LinkedHashMap<>(shellClassMap);
    }

    public boolean isNotEmpty() {
        return !shellClassMap.isEmpty();
    }

    public Set<String> getSupportedShellTypes() {
        return shellClassMap.keySet();
    }

    public Map<String, Pair<String, String>> getShellClassMap(InjectorMapping injectorMapping) {
        Map<String, Pair<String, String>> result = new LinkedHashMap<>();
        for (String type : injectorMapping.getSupportedShellTypes()) {
            String shellClassName = shellClassMap.get(type);
            String injectorClassName = injectorMapping.getInjector(type);
            if (shellClassName != null && injectorClassName != null) {
                result.put(type, Pair.of(shellClassName, injectorClassName));
            }
        }
        return result;
    }
}
