package com.reajason.javaweb.memshell.server;

import com.reajason.javaweb.Server;
import com.reajason.javaweb.memshell.ShellTypeSuffix;
import com.reajason.javaweb.memshell.config.InjectorConfig;
import com.reajason.javaweb.memshell.config.ShellConfig;
import com.reajason.javaweb.memshell.config.ShellToolConfig;
import com.reajason.javaweb.utils.NameSampler;
import com.reajason.javaweb.utils.StringUtils;
import com.reajason.javaweb.utils.tuple.Pair;

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

    /**
     * shellBytes 生成完成后的 server 专属改写钩子：可改写字节码（如 Jetty Handler 按版本换父类）、
     * 向 {@code injectorConfig} 贡献 helper 类（如 Dubbo 接口、WebSocket 绕过 helper）、调整 urlPattern。
     * 默认原样返回。
     *
     * @return 改写后的 shell 字节码
     */
    public byte[] postProcessShellBytes(byte[] shellBytes, ShellConfig shellConfig,
                                        ShellToolConfig shellToolConfig, InjectorConfig injectorConfig) {
        return shellBytes;
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
        // 与 getShellInjectorPair 共用同一份过滤结果：缺少注入器模板的类型不能对外暴露，
        // 否则会广告出一个生成时必然失败的类型
        return Collections.unmodifiableSet(toolMapping.getShellClassMap(getShellInjectorMapping()).keySet());
    }

    public Set<String> getSupportedShellTools() {
        return Collections.unmodifiableSet(map.keySet());
    }

    /**
     * @return left: shell template class name, right: injector template class name
     */
    public Pair<String, String> getShellInjectorPair(String shellTool, String shellType) {
        if (StringUtils.isBlank(shellTool)) {
            throw new IllegalArgumentException("shellTool is required");
        }
        ToolMapping mapping = map.get(shellTool);
        if (mapping == null) {
            throw new UnsupportedOperationException("please implement shell type: " + shellType + " for " + shellTool);
        }
        Map<String, Pair<String, String>> shellClassMap = mapping.getShellClassMap(getShellInjectorMapping());
        return shellClassMap.get(shellType);
    }

    /**
     * 生成内存马类名：类名会被放进与目标中间件同名的包下，让内存马在类加载器视角里不显突兀。
     * <p>
     * 结构为 {@code <中间件包名>.<包名段>.<前缀词><中段词><自然后缀>}，例如
     * {@code org.apache.http.web.handlers.session.SessionValidationFilter}。
     * 包名沿用各中间件自身常见的内部路径，让内存马在类加载器视角里不显突兀。
     * 自然后缀由 {@link ShellTypeSuffix} 抹掉 {@code Jakarta}/{@code Agent} 等生成器内部标记。
     *
     * @param serverName 中间件名称，取值见 {@link com.reajason.javaweb.Server}
     * @param shellType  内存马类型，用于推导类名后缀
     */
    public static String generateShellClassName(String serverName, String shellType) {
        NameSampler.SampledName name = NameSampler.sample(toClassNameSuffix(shellType));
        return getWebPackageName(serverName)
                + "." + name.getPackageSegment()
                + "." + name.getSimpleName();
    }

    /**
     * 把自定义 shellType 规范成采样器接受的 PascalCase 后缀。
     * <p>
     * {@link ShellTypeSuffix#of} 对未登记类型原样返回，但自定义类型可能是
     * {@code my_filter} / {@code myFilter} 这类形式，直接交给 {@link NameSampler}
     * 会因正则或长度限制失败。这里只影响类名的“自然后缀”，不影响注入逻辑。
     */
    static String toClassNameSuffix(String shellType) {
        String suffix = ShellTypeSuffix.of(shellType);
        if (NameSampler.isValidSuffix(suffix)) {
            return suffix;
        }
        StringBuilder sanitized = new StringBuilder();
        for (String part : suffix.split("[^A-Za-z0-9]+")) {
            if (part.isEmpty()) {
                continue;
            }
            sanitized.append(Character.toUpperCase(part.charAt(0)));
            if (part.length() > 1) {
                sanitized.append(part.substring(1));
            }
        }
        if (sanitized.length() == 0) {
            return "Handler";
        }
        if (!Character.isJavaIdentifierStart(sanitized.charAt(0))) {
            sanitized.insert(0, "Custom");
        }
        return NameSampler.isValidSuffix(sanitized.toString()) ? sanitized.toString() : "Handler";
    }

    /**
     * 各中间件对应的、看起来像是框架自身组件的包名
     */
    public static String getWebPackageName(String serverName) {
        switch (serverName) {
            case Server.Jetty5:
                return "org.mortbay.jetty.servlet.handlers";
            case Server.Jetty:
                return "org.eclipse.jetty.servlet.handlers";
            case Server.Undertow:
                return "io.undertow.servlet.handlers";
            case Server.SpringWebMvc:
                return "org.springframework.boot.mvc.handlers";
            case Server.SpringWebFlux:
                return "org.springframework.boot.webflux.handlers";
            case Server.WebSphere:
                return "com.ibm.ws.webcontainer.handlers";
            case Server.WebLogic:
                return "weblogic.servlet.internal.handlers";
            case Server.Resin:
                return "com.caucho.server.dispatch.handlers";
            case Server.Resin2:
                return "com.caucho.server.http.handlers";
            case Server.BES:
                return "com.bes.enterprise.webtier.web.handlers";
            case Server.Apusic:
                return "com.apusic.web.handlers";
            case Server.InforSuite:
                return "com.cvicse.inforsuite.web.handlers";
            default:
                return "org.apache.http.web.handlers";
        }
    }
}
