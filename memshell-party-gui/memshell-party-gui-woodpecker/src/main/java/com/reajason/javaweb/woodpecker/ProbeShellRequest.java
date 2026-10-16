package com.reajason.javaweb.woodpecker;

import com.reajason.javaweb.desktop.memshell.controller.ProbeShellFormController;
import com.reajason.javaweb.desktop.memshell.model.DesktopProbeShellGenerateResult;
import com.reajason.javaweb.desktop.memshell.model.ProbeShellFormState;
import com.reajason.javaweb.desktop.memshell.service.ConfigCatalogService;
import com.reajason.javaweb.desktop.memshell.service.ProbeConfigCatalogService;
import com.reajason.javaweb.desktop.memshell.service.ProbeGenerationService;
import com.reajason.javaweb.desktop.memshell.validation.ProbeShellValidator;
import com.reajason.javaweb.packer.Packers;
import me.gv7.woodpecker.plugin.IResultOutput;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

/**
 * 参数文本框 → 探测马生成请求，与 {@link MemShellRequest} 同一套做法：
 * 联动与默认值交给 GUI SDK 的 {@link ProbeShellFormController}，本类只做「填了值才设置」。
 */
final class ProbeShellRequest {

    private static final ConfigCatalogService CATALOG_SERVICE = new ConfigCatalogService();

    private final ProbeShellFormController controller;
    private final ProbeShellFormState state;
    private final Map<String, Object> args;
    private final List<String> notices = new ArrayList<String>();

    private ProbeShellRequest(ProbeShellFormController controller, Map<String, Object> args) {
        this.controller = controller;
        this.state = controller.getState();
        this.args = args == null ? Collections.<String, Object>emptyMap() : args;
    }

    static ProbeShellRequest from(Map<String, Object> args) {
        ProbeShellRequest request = new ProbeShellRequest(
                new ProbeShellFormController(CATALOG_SERVICE, new ProbeShellValidator()), args);
        request.applyArgs();
        request.fallBackProbeContent();
        return request;
    }

    private void applyArgs() {
        // 先定探测方式：它会重置探测内容与 Sleep 参数
        apply("probeMethod", controller::setProbeMethod);
        apply("probeContent", controller::setProbeContent);
        apply("targetJdkVersion", controller::setTargetJdkVersion);
        apply("packingMethod", controller::setPacker);
        apply("server", controller::setServer);
        apply("host", controller::setHost);
        apply("sleepServer", controller::setSleepServer);
        apply("seconds", controller::setSeconds);
        apply("reqParamName", controller::setReqParamName);
        apply("commandTemplate", controller::setCommandTemplate);
        apply("shellClassName", controller::setShellClassName);

        applyFlag("shrink", true, controller::setShrink);
        applyFlag("staticInitialize", true, controller::setStaticInitialize);
        applyFlag("byPassJavaModule", false, controller::setByPassJavaModule);
        applyFlag("lambdaSuffix", false, controller::setLambdaSuffix);
        applyFlag("debug", false, controller::setDebug);
    }

    /**
     * 预填/上一次填的探测内容在换探测方式后可能失效（如 Command 只属于 ResponseBody），
     * 这里是「名字认识但当前探测方式不支持」的情况，回落到首个可选内容并提示。
     */
    private void fallBackProbeContent() {
        String probeContent = state.getProbeContent().trim();
        List<String> validContents = controller.getProbeContents();
        if (probeContent.isEmpty() || validContents.isEmpty() || validContents.contains(probeContent)
                || !isKnownProbeContent(probeContent)) {
            return;
        }
        state.setProbeContent(validContents.get(0));
        notices.add("probeContent=" + probeContent + " 不适用于 " + state.getProbeMethod()
                + "，已改用 " + validContents.get(0) + "（可选值：" + String.join(", ", validContents) + "）");
    }

    /**
     * @return 该探测内容在任意探测方式下可用 —— 用来区分「换了探测方式导致失效」和「名字写错了」
     */
    private static boolean isKnownProbeContent(String probeContent) {
        ProbeConfigCatalogService probeCatalog = new ProbeConfigCatalogService(CATALOG_SERVICE);
        for (String method : probeCatalog.getProbeMethods()) {
            if (probeCatalog.getProbeContents(method).contains(probeContent)) {
                return true;
            }
        }
        return false;
    }

    void printSummary(IResultOutput output) {
        Output.info(output, "探测方式: " + state.getProbeMethod() + " / " + state.getProbeContent());
        Output.info(output, "打包方式: " + state.getPackingMethod());
        Output.info(output, "目标 JDK: " + state.getTargetJdkVersion()
                + " " + CATALOG_SERVICE.getTargetJdkLabel(state.getTargetJdkVersion())
                + "，BypassJavaModule: " + state.isByPassJavaModule());
        for (String notice : notices) {
            Output.warn(output, notice);
        }
    }

    boolean printFieldErrors(IResultOutput output) {
        String probeMethod = unknownValue("probeMethod", controller.getProbeMethods());
        if (probeMethod != null) {
            Output.fail(output, probeMethod);
            return true;
        }
        if (!isValidProbeContent()) {
            Output.fail(output, "不支持的 probeContent: " + state.getProbeContent()
                    + "，可选值：" + String.join(", ", controller.getProbeContents()));
            return true;
        }
        String packer = state.getPackingMethod();
        if (isUnknownPacker(packer)) {
            Output.fail(output, "不支持的 packingMethod: " + packer);
            Output.info(output, "可选值：" + packerNames());
            return true;
        }

        ProbeShellValidator.Result result = controller.validate();
        if (result.isValid()) {
            return false;
        }
        for (Map.Entry<String, String> error : result.getFieldErrors().entrySet()) {
            Output.fail(output, error.getKey() + ": " + error.getValue());
        }
        return true;
    }

    /**
     * 校验的是控制器里的最终取值而不是原始参数：失效的内容已在 {@link #fallBackProbeContent()} 里回落。
     */
    private boolean isValidProbeContent() {
        String probeContent = state.getProbeContent().trim();
        return probeContent.isEmpty() || controller.getProbeContents().contains(probeContent);
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

    private static boolean isUnknownPacker(String packer) {
        try {
            Packers.valueOf(packer);
            return false;
        } catch (RuntimeException e) {
            return true;
        }
    }

    DesktopProbeShellGenerateResult generate() {
        return new ProbeGenerationService().generate(state);
    }

    private void apply(String name, Setter setter) {
        String value = Args.str(args, name, "");
        if (!value.isEmpty()) {
            setter.set(value);
        }
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
        List<String> names = new ArrayList<String>();
        for (Packers packer : Packers.values()) {
            names.add(packer.name());
        }
        return String.join(", ", names);
    }

    private interface Setter {
        void set(String value);
    }

    private interface FlagSetter {
        void set(boolean value);
    }
}
