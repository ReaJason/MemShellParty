package com.reajason.javaweb.memshell.server;

import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.tuple.Pair;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

/**
 * @author ReaJason
 * @since 2024/12/7
 */
public abstract class AbstractServer {

    private final Map<String, ToolMapping> map = new LinkedHashMap<>();

    /**
     * 定义注入器映射
     *
     * @return 注入器映射
     */
    public abstract InjectorMapping getShellInjectorMapping();

    public Class<?> getListenerInterceptor() {
        return null;
    }

    public void addToolMapping(String shellTool, ToolMapping mapping) {
        map.put(shellTool, mapping);
    }

    /**
     * 获取内存马功能所支持的注入类型列表
     *
     * @param shellTool 内存马功能
     * @return shellTypes
     */
    public Set<String> getSupportedShellTypes(String shellTool) {
        ToolMapping toolMapping = map.get(shellTool);
        if (toolMapping == null) {
            return Collections.emptySet();
        }
        return Collections.unmodifiableSet(toolMapping.getSupportedShellTypes());
    }

    public Set<String> getSupportedShellTools() {
        return Collections.unmodifiableSet(map.keySet());
    }

    public Pair<Class<?>, Class<?>> getShellInjectorPair(String shellTool, String shellType) {
        if (StringUtils.isBlank(shellTool)) {
            throw new IllegalArgumentException("shellTool is required");
        }
        ToolMapping mapping = map.get(shellTool);
        if (mapping == null) {
            throw new UnsupportedOperationException("please implement shell type: " + shellType + " for " + shellTool);
        }
        Map<String, Pair<Class<?>, Class<?>>> shellClassMap = mapping.getShellClassMap(getShellInjectorMapping());
        return shellClassMap.get(shellType);
    }
}
