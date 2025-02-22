package com.reajason.javaweb.memshell.server;

import com.reajason.javaweb.memshell.ShellTool;
import org.apache.commons.lang3.tuple.Pair;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * @author ReaJason
 * @since 2024/12/7
 */
public abstract class AbstractShell {

    private final Map<ShellTool, ToolMapping> map = new LinkedHashMap<>();

    public AbstractShell() {
        init();
    }

    /**
     * 定义注入器映射
     *
     * @return 注入器映射
     */
    abstract InjectorMapping getShellInjectorMapping();

    protected void addToolMapping(ShellTool shellTool, ToolMapping mapping) {
        map.put(shellTool, mapping);
    }

    /**
     * 初始化方法，用来定义 shellToolMapping 填充 map
     */
    abstract void init();


    /**
     * 获取内存马功能所支持的注入类型列表
     *
     * @param shellTool 内存马功能
     * @return shellTypes
     */
    public List<String> getSupportedShellTypes(ShellTool shellTool) {
        ToolMapping toolMapping = map.get(shellTool);
        if (toolMapping == null) {
            return Collections.emptyList();
        }
        return toolMapping.getSupportedShellTypes();
    }

    public Pair<Class<?>, Class<?>> getShellInjectorPair(ShellTool shellTool, String shellType) {
        ToolMapping mapping = map.get(shellTool);
        if (mapping == null) {
            throw new UnsupportedOperationException("please implement shell type: " + shellType + " for " + shellTool);
        }
        Map<String, Pair<Class<?>, Class<?>>> shellClassMap = mapping.getShellClassMap(getShellInjectorMapping());
        return shellClassMap.get(shellType);
    }
}
