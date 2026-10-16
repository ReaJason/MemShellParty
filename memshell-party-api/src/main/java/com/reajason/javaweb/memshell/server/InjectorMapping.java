package com.reajason.javaweb.memshell.server;

import lombok.Builder;
import lombok.Singular;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

/**
 * Maps shell types to injector template class names.
 *
 * <p>Templates are referenced by binary name, never as {@link Class} literals: loading a
 * template class would drag its supertypes (servlet, reactor, server-specific APIs) onto
 * the consumer's classpath. Generation resolves templates as bytes via the class loader.
 *
 * @author ReaJason
 * @since 2025/2/21
 */
@Builder
public class InjectorMapping {

    /**
     * shellType -&gt; injector template class binary name
     */
    @Singular("addInjector")
    private final Map<String, String> injectorMap;

    public InjectorMapping(Map<String, String> injectorMap) {
        this.injectorMap = new LinkedHashMap<>(injectorMap);
    }

    public String getInjector(String type) {
        return injectorMap.get(type);
    }

    public Set<String> getSupportedShellTypes() {
        return Collections.unmodifiableSet(injectorMap.keySet());
    }
}
