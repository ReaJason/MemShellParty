package com.reajason.javaweb.desktop.memshell.service;

import com.reajason.javaweb.desktop.memshell.model.DesktopMemShellGenerateResult;
import com.reajason.javaweb.desktop.memshell.model.InfoRow;
import com.reajason.javaweb.desktop.memshell.model.ToolParamLabels;
import com.reajason.javaweb.memshell.MemShellResult;
import com.reajason.javaweb.memshell.ShellTool;
import com.reajason.javaweb.memshell.ToolParamVisibility;
import com.reajason.javaweb.memshell.config.ConfigField;
import com.reajason.javaweb.memshell.config.ShellConfig;
import com.reajason.javaweb.memshell.config.ShellToolConfig;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.ArrayList;
import java.util.List;

/**
 * 生成结果基本信息的无界面描述：只包含「生成后才知道」的值（随机密码/密钥、派生加密器、
 * 实际类名与大小等），表单里填过的 server/tool/类型不再重复。
 * <p>
 * 界面（{@code BasicInfoPanel}）与 Woodpecker 插件的文本输出共用这一份行集，
 * 避免两处展示口径漂移；行序对齐 web 端 basic-info.tsx。
 * <p>
 * 行集完全由 {@code @ConfigField} 目录 + 反射驱动：本模块编译期不认识任何内置工具类，
 * 只引 server 提供者即可生成（下游自带发行版很常见）。
 */
public final class ResultInfoService {

    private ResultInfoService() {
    }

    /**
     * 完整的生成结果摘要：工具参数行 + 固定的类名行。
     */
    public static List<InfoRow> describe(DesktopMemShellGenerateResult result) {
        MemShellResult r = result.getMemShellResult();
        List<InfoRow> rows = describeTool(r.getShellConfig(), r.getShellToolConfig());
        rows.add(new InfoRow("注入器类名", r.getInjectorClassName() + " (" + r.getInjectorSize() + " bytes)",
                r.getInjectorClassName(), true));
        rows.add(new InfoRow("内存马类名", r.getShellClassName() + " (" + r.getShellSize() + " bytes)",
                r.getShellClassName(), true));
        rows.addAll(describeObfuscation(r.getObfuscationInfo()));
        return rows;
    }

    /**
     * 混淆相关信息行：不展示「已启用/档位/前后体积」摘要 —— 类名行里的字节数已经足够说明
     * 产物是否被混淆；只有会直接影响使用的 Header 载荷超限预警才需要占一行。
     */
    public static List<InfoRow> describeObfuscation(com.reajason.javaweb.memshell.obfuscation.ObfuscationInfo obf) {
        List<InfoRow> rows = new ArrayList<InfoRow>();
        if (obf == null || !obf.isEnabled()) {
            return rows;
        }
        if (obf.isHeaderPayloadTooLarge() && obf.getPackedPayloadSize() != null) {
            rows.add(InfoRow.warning("载荷体积预警",
                    "打包后载荷 " + obf.getPackedPayloadSize() + " 字节，超过 "
                            + com.reajason.javaweb.memshell.obfuscation.ObfuscationInfo.HEADER_PAYLOAD_WARNING_THRESHOLD
                            + " 字节：经 HTTP Header 传输可能触发 400 Bad Request"));
        }
        return rows;
    }

    /**
     * 工具参数行：按 {@code @ConfigField} 的字段声明顺序逐行取值，名字走
     * {@link ToolParamLabels}（注解的 {@code label} 优先，与表单同源）。
     * <p>
     * 参数表从 {@code toolConfig} 自己的类上读，而不是查注册表：插件工具（含测试里
     * 现造的 config）没注册也能出全行集，{@code shellConfig} 为 null 时同样成立。
     * <p>
     * 两处特殊处理：
     * <ul>
     *   <li>Godzilla 的「加密器」不是配置字段而是由挂载类型派生，对齐 web basic-info；</li>
     *   <li>请求头名/值合成一行「请求头」展示 —— 按字段名配对而不是 {@code HeaderAware}，
     *       因为 Suo5/NeoreGeorg 的请求头行不走那个接口，按接口判定会让它们多出一行。</li>
     * </ul>
     */
    public static List<InfoRow> describeTool(ShellConfig shellConfig, ShellToolConfig toolConfig) {
        List<InfoRow> rows = new ArrayList<InfoRow>();
        if (toolConfig == null) {
            return rows;
        }
        String shellTool = shellConfig == null ? null : shellConfig.getShellTool();
        String server = shellConfig == null ? null : shellConfig.getServer();
        String shellType = shellConfig == null ? null : shellConfig.getShellType();

        // 请求头名/值合成一行，读到名时把值一起取走，值本身不再单独成行
        String headerName = null;
        String headerValue = null;
        for (Field field : configFields(toolConfig.getClass())) {
            String name = field.getName();
            if (!ToolParamVisibility.isVisible(shellTool, name, server, shellType)) {
                continue;
            }
            if ("headerName".equals(name)) {
                // Godzilla 的派生加密器排在请求头之前（对齐 web basic-info 的 pass/key/encryptor/header）
                if (ShellTool.Godzilla.equals(shellTool)) {
                    rows.add(new InfoRow("加密器", deriveGodzillaEncryptor(shellType)));
                }
                headerName = stringValue(toolConfig, name);
                headerValue = stringValue(toolConfig, "headerValue");
                continue;
            }
            if ("headerValue".equals(name)) {
                continue;
            }
            String value = stringValue(toolConfig, name);
            // 命令模板这类可选参数没填就不占一行；随机生成的密码/密钥则一定有值
            if (value == null || value.isEmpty()) {
                continue;
            }
            rows.add(new InfoRow(ToolParamLabels.of(name, labelOf(field)), value));
        }
        if (headerName != null) {
            rows.add(new InfoRow("请求头", headerName + ": " + (headerValue == null ? "" : headerValue)));
        }
        return rows;
    }

    /**
     * 可配置字段，顺序与 {@code ToolConfigFactory.describeParams} 一致（子类在前，即声明顺序）。
     * {@link ShellToolConfig} 基类的生成配置（shellClassName / shellTemplateClassName）没标注解，
     * 天然不在行集里 —— 它们由生成器填充，固定的类名行已经展示过。
     */
    private static List<Field> configFields(Class<?> configClass) {
        List<Field> fields = new ArrayList<Field>();
        for (Class<?> type = configClass; type != null && type != Object.class; type = type.getSuperclass()) {
            for (Field field : type.getDeclaredFields()) {
                if (Modifier.isStatic(field.getModifiers())) {
                    continue;
                }
                if (field.getAnnotation(ConfigField.class) != null) {
                    fields.add(field);
                }
            }
        }
        return fields;
    }

    private static String labelOf(Field field) {
        return field.getAnnotation(ConfigField.class).label();
    }

    /**
     * 读一个 config 字段的展示值：{@code @ConfigField} 参数一律 String/枚举，枚举取常量名。
     * 字段不存在（工具没注册、类不在类路径）或读取失败时返回 {@code null}，该行整体跳过。
     */
    private static String stringValue(ShellToolConfig toolConfig, String paramName) {
        Method getter = getterOf(toolConfig.getClass(), paramName);
        if (getter == null) {
            return null;
        }
        try {
            // 工具 config 类可能是调用方包内的非公开类（插件工具很常见），只反射 public 方法不够：
            // 声明类本身不可见时 invoke 会抛 IllegalAccessException，于是参数行整体消失
            if (!getter.isAccessible()) {
                getter.setAccessible(true);
            }
            Object value = getter.invoke(toolConfig);
            if (value == null) {
                return null;
            }
            return value instanceof Enum ? ((Enum<?>) value).name() : String.valueOf(value);
        } catch (Exception ignored) {
            // 单个属性读取失败不影响整体展示
            return null;
        }
    }

    private static Method getterOf(Class<?> configClass, String paramName) {
        if (paramName == null || paramName.isEmpty()) {
            return null;
        }
        String suffix = Character.toUpperCase(paramName.charAt(0)) + paramName.substring(1);
        for (String name : new String[]{"get" + suffix, "is" + suffix}) {
            try {
                return configClass.getMethod(name);
            } catch (NoSuchMethodException ignored) {
                // 试下一个 getter 命名
            }
        }
        return null;
    }

    /**
     * 对齐 web basic-info 的 Godzilla 派生加密器展示。
     */
    private static String deriveGodzillaEncryptor(String shellType) {
        if (shellType != null && shellType.contains("WebSocket")) {
            return "JAVA_WEBSOCKET_AES_RAW";
        }
        if (shellType != null && shellType.contains("Dubbo")) {
            return "DUBBO_XOR_BASE64";
        }
        return "JAVA_AES_BASE64";
    }
}
