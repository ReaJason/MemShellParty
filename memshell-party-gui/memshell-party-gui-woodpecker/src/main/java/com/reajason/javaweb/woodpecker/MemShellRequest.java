package com.reajason.javaweb.woodpecker;

import com.reajason.javaweb.desktop.memshell.controller.MemShellFormController;
import com.reajason.javaweb.desktop.memshell.model.DesktopMemShellGenerateResult;
import com.reajason.javaweb.desktop.memshell.model.MemShellFormState;
import com.reajason.javaweb.desktop.memshell.service.ConfigCatalogService;
import com.reajason.javaweb.desktop.memshell.service.CustomClassNameParser;
import com.reajason.javaweb.desktop.memshell.service.GenerationService;
import com.reajason.javaweb.desktop.memshell.validation.MemShellValidator;
import com.reajason.javaweb.memshell.PackerRegistry;
import com.reajason.javaweb.memshell.ShellTool;
import com.reajason.javaweb.memshell.ToolConfigFactory;
import me.gv7.woodpecker.plugin.IResultOutput;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * 参数文本框 → 生成请求。
 *
 * <p>列转状态交给 GUI SDK 的 {@link MemShellFormController}（联动、回落、默认值都在它那边），
 * 本类只负责「填了值才设置」：留空的参数一律不动控制器已算好的值，这样「留空=自动/随机」
 * 对每个参数都成立。
 *
 * <p>设置顺序有讲究：{@code setServer}/{@code setShellTool}/{@code setShellType} 会重置挂载路径、
 * 工具参数、目标 JDK 与类名，所以这些必须在它们之后设置。
 */
final class MemShellRequest {

    private static final ConfigCatalogService CATALOG_SERVICE = new ConfigCatalogService();

    private final MemShellFormController controller;
    private final MemShellFormState state;
    private final Map<String, Object> args;
    private final List<String> notices = new ArrayList<String>();
    /**
     * 当前 shellTool 支持的工具参数名，setter 阶段按它过滤（见 {@link #applyToolParam}）。
     */
    private Set<String> toolParams = Collections.emptySet();

    private MemShellRequest(MemShellFormController controller, Map<String, Object> args) {
        this.controller = controller;
        this.state = controller.getState();
        this.args = args == null ? Collections.<String, Object>emptyMap() : args;
    }

    static MemShellRequest from(Map<String, Object> args) {
        MemShellRequest request = new MemShellRequest(
                new MemShellFormController(CATALOG_SERVICE, new MemShellValidator()), args);
        request.applyArgs();
        request.fallBackShellType();
        request.resolveCustomShellClassName();
        return request;
    }

    private void applyArgs() {
        // 先定服务端/工具/类型：这三步会重置其余联动字段
        apply("server", controller::setServer);
        apply("serverVersion", controller::setServerVersion);
        apply("shellTool", controller::setShellTool);
        apply("shellType", controller::setShellType);

        // 其后是会被上一步重置的字段，以及纯独立字段
        apply("targetJdkVersion", controller::setTargetJdkVersion);
        apply("urlPattern", controller::setUrlPattern);
        apply("packingMethod", controller::setPacker);
        apply("shellClassName", controller::setShellClassName);
        apply("injectorClassName", controller::setInjectorClassName);

        // 工具参数：写进统一的状态 map（key 即 config 字段名），只有当前工具用得上的才生效
        toolParams = paramNamesOf(state.getShellTool());
        applyToolParam("pass");
        applyToolParam("key");
        applyToolParam("paramName");
        applyToolParam("template");
        applyToolParam("headerName");
        applyToolParam("headerValue");
        applyToolParam("encryptor");
        applyToolParam("implementationClass");
        applyToolParam("shellClassBase64");

        // 布尔参数最后设置：控制器会按目标 JDK 自动决定 byPassJavaModule，显式填了才覆盖
        applyFlag("shrink", true, controller::setShrink);
        applyFlag("staticInitialize", true, controller::setStaticInitialize);
        applyFlag("byPassJavaModule", false, controller::setByPassJavaModule);
        applyFlag("lambdaSuffix", false, controller::setLambdaSuffix);
        applyFlag("debug", false, controller::setDebug);
    }

    /**
     * 预填的 shellType 在换服务端/工具后可能失效（如把 server 从 Tomcat 改成 SpringWebFlux 后 Listener 不存在）。
     * 桌面端表单此时会自动回落到首个可用类型，这里照做并提示；名字本身不认识的不算回落，留给校验报错。
     */
    private void fallBackShellType() {
        String shellType = state.getShellType().trim();
        List<String> validTypes = controller.getShellTypesForCurrentTool();
        if (shellType.isEmpty() || validTypes.isEmpty() || validTypes.contains(shellType)
                || !isKnownShellType(shellType)) {
            return;
        }
        // 直接改 state：setShellType 会把挂载路径重置回 /*，那会盖掉用户显式填的 urlPattern
        state.setShellType(validTypes.get(0));
        notices.add("shellType=" + shellType + " 不适用于 " + state.getServer() + " / " + state.getShellTool()
                + "，已改用 " + validTypes.get(0) + "（可选值：" + String.join(", ", validTypes) + "）");
    }

    /**
     * @return 该类型名在任意服务端/工具下可用 —— 用来区分「换了服务端导致失效」和「名字写错了」
     */
    private static boolean isKnownShellType(String shellType) {
        for (Map<String, List<String>> tools : CATALOG_SERVICE.load().getShellTypeCatalog().asMap().values()) {
            for (List<String> types : tools.values()) {
                if (types.contains(shellType)) {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * Custom 工具：类名留空时从 Base64 字节码里解析（对齐桌面端表单的自动填充），
     * 否则生成器会拿随机类名 rename，与用户提供的类对不上。
     */
    private void resolveCustomShellClassName() {
        String shellClassBase64 = state.getToolParam(MemShellFormState.PARAM_SHELL_CLASS_BASE64);
        if (ShellTool.Custom.equals(state.getShellTool())
                && state.getShellClassName().trim().isEmpty()
                && !shellClassBase64.trim().isEmpty()) {
            state.setShellClassName(
                    new CustomClassNameParser().parseClassNameFromBase64(shellClassBase64));
        }
    }

    /**
     * 参数确认行：回显控制器联动后的最终取值（留空自动的参数只有这里能看到实际结果）。
     */
    void printSummary(IResultOutput output) {
        Output.info(output, "服务端: " + state.getServer() + " (" + state.getServerVersion() + ")");
        Output.info(output, "工具 / 类型: " + state.getShellTool() + " / " + state.getShellType());
        Output.info(output, "打包方式: " + (state.getPackingMethod().isEmpty()
                ? PackerRegistry.RAW_LABEL : state.getPackingMethod()));
        Output.info(output, "目标 JDK: " + state.getTargetJdkVersion()
                + " " + CATALOG_SERVICE.getTargetJdkLabel(state.getTargetJdkVersion())
                + "，BypassJavaModule: " + state.isByPassJavaModule());
        for (String notice : notices) {
            Output.warn(output, notice);
        }
    }

    /**
     * 校验失败时逐条打印字段错误。
     *
     * <p>先查「填了但不存在」的取值：控制器遇到不认识的服务端/工具只会把类型清空，
     * 最后报的是「请选择内存马挂载类型」，用户根本看不出是哪个参数写错了。
     *
     * @return 是否有错（有错就不用继续生成了）
     */
    boolean printFieldErrors(IResultOutput output) {
        String server = unknownValue("server", controller.getServers());
        if (server != null) {
            Output.fail(output, server);
            return true;
        }
        String shellTool = unknownValue("shellTool", controller.getShellTools());
        if (shellTool != null) {
            Output.fail(output, shellTool);
            return true;
        }
        if (!isValidShellType()) {
            Output.fail(output, "不支持的 shellType: " + state.getShellType()
                    + "，可选值：" + String.join(", ", controller.getShellTypesForCurrentTool()));
            return true;
        }
        String packer = state.getPackingMethod();
        if (isUnknownPacker(packer)) {
            Output.fail(output, "不支持的 packingMethod: " + packer);
            Output.info(output, "可选值：" + packerNames());
            return true;
        }

        MemShellValidator.Result result = controller.validate();
        if (result.isValid()) {
            return false;
        }
        for (Map.Entry<String, String> error : result.getFieldErrors().entrySet()) {
            Output.fail(output, error.getKey() + ": " + error.getValue());
        }
        return true;
    }

    /**
     * 校验的是控制器里的最终取值而不是原始参数：失效的类型已在 {@link #fallBackShellType()} 里回落到可用值。
     */
    private boolean isValidShellType() {
        String shellType = state.getShellType().trim();
        return shellType.isEmpty() || controller.getShellTypesForCurrentTool().contains(shellType);
    }

    /**
     * @return 参数填了但不属于可选值时的提示；没填或填对返回 null
     */
    private String unknownValue(String paramName, List<String> validValues) {
        String value = Args.str(args, paramName, "");
        if (value.isEmpty() || validValues.contains(value)) {
            return null;
        }
        return "不支持的 " + paramName + ": " + value + "，可选值：" + String.join(", ", validValues);
    }

    /**
     * 空打包方式合法（输出 raw Base64），非空时必须是注册表里认识的名称。
     */
    private static boolean isUnknownPacker(String packer) {
        return !packer.isEmpty() && !PackerRegistry.getInstance().contains(packer);
    }

    DesktopMemShellGenerateResult generate() {
        return new GenerationService().generate(state);
    }

    private void apply(String name, Setter setter) {
        String value = Args.str(args, name, "");
        if (!value.isEmpty()) {
            setter.set(value);
        }
    }

    /**
     * 工具参数：只有当前 shellTool 的目录（{@code @ConfigField}）里有这个参数才写进状态 ——
     * 写了别的工具的参数会被生成器直接拒掉，这里给个提示后忽略。
     */
    private void applyToolParam(String name) {
        String value = Args.str(args, name, "");
        if (value.isEmpty()) {
            return;
        }
        if (toolParams.contains(name)) {
            controller.setToolParam(name, value);
            return;
        }
        notices.add(name + " 不适用于 " + state.getShellTool() + "，已忽略");
    }

    private static Set<String> paramNamesOf(String tool) {
        Set<String> names = new LinkedHashSet<String>();
        for (ToolConfigFactory.ConfigParam param : ToolConfigFactory.describeParams(tool)) {
            names.add(param.getName());
        }
        return names;
    }

    /**
     * 布尔参数认得出来就按填的走，认不出来（如 ture）按默认值处理并提示 —— 静默吞掉会把用户坑在结果里。
     */
    private void applyFlag(String name, boolean fallback, FlagSetter setter) {
        Boolean value = Args.parseFlag(args, name);
        if (value == null) {
            if (!Args.str(args, name, "").isEmpty()) {
                notices.add("布尔参数 " + name + " 的值「" + Args.str(args, name, "")
                        + "」无法识别（用 true/false），按 " + fallback + " 处理");
                setter.set(fallback);
            }
            return;
        }
        setter.set(value.booleanValue());
    }

    private static String packerNames() {
        return String.join(", ", PackerRegistry.getInstance().getNames());
    }

    private interface Setter {
        void set(String value);
    }

    private interface FlagSetter {
        void set(boolean value);
    }
}
