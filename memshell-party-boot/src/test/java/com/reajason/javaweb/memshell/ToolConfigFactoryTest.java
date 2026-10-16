package com.reajason.javaweb.memshell;

import com.reajason.javaweb.GenerationException;
import com.reajason.javaweb.memshell.config.ConfigField;
import com.reajason.javaweb.memshell.config.ShellToolConfig;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 配置目录契约：目录（{@code @ConfigField}）与绑定必须始终一致 ——
 * 参数顺序、分组、可选值漂移，或者注解漏写导致字段从表单里消失，都在这里炸。
 *
 * @author ReaJason
 * @since 3.0.0
 */
class ToolConfigFactoryTest {

    @Test
    void everyRegisteredToolExposesItsParamsInRegistryOrder() {
        List<String> toolNames = new ArrayList<>();
        for (ToolConfigFactory.ToolConfigDescriptor descriptor : ToolConfigFactory.describeAll()) {
            toolNames.add(descriptor.getTool());
            assertFalse(descriptor.getParams().isEmpty(), descriptor.getTool() + " exposes no params");
        }
        assertEquals(MemShellRegistry.getInstance().getSupportedTools(), toolNames);
    }

    /**
     * 表单顺序 = 字段声明顺序，不能再依赖 Lombok builder 的方法顺序（那是实现细节）。
     */
    @Test
    void paramOrderFollowsFieldDeclarationOrder() {
        assertEquals(Arrays.asList("paramName", "headerName", "headerValue", "encryptor",
                        "implementationClass", "template"),
                namesOf(ShellTool.Command));
        assertEquals(Arrays.asList("pass", "key", "headerName", "headerValue"),
                namesOf(ShellTool.Godzilla));
        assertEquals(Arrays.asList("shellClassBase64"), namesOf(ShellTool.Custom));
    }

    @Test
    void groupAndOptionsComeFromTheConfigClass() {
        Map<String, ToolConfigFactory.ConfigParam> command = paramsOf(ShellTool.Command);
        assertEquals(ConfigField.Group.BASIC, command.get("paramName").getGroup());
        assertEquals(ConfigField.Group.ADVANCED, command.get("encryptor").getGroup());
        assertEquals(ConfigField.Group.ADVANCED, command.get("template").getGroup());
        assertEquals("enum", command.get("encryptor").getType());
        assertEquals(Arrays.asList("RAW", "BASE64", "DOUBLE_BASE64"), command.get("encryptor").getOptions());
        assertEquals("string", command.get("paramName").getType());
        assertTrue(command.get("paramName").getOptions().isEmpty());

        for (ToolConfigFactory.ConfigParam param : paramsOf(ShellTool.Godzilla).values()) {
            assertEquals(ConfigField.Group.BASIC, param.getGroup());
        }
    }

    /**
     * 漂移保险丝：目录里列出来的每个参数都必须真的能绑定上，否则表单会画出一个填了没用（或反之）的字段。
     */
    @Test
    void everyCataloguedParamIsBindable() {
        for (ToolConfigFactory.ToolConfigDescriptor descriptor : ToolConfigFactory.describeAll()) {
            Map<String, String> params = new LinkedHashMap<>();
            for (ToolConfigFactory.ConfigParam param : descriptor.getParams()) {
                params.put(param.getName(), sampleValue(param));
            }
            ShellToolConfig config = ToolConfigFactory.fromParams(descriptor.getTool(), params);
            for (Map.Entry<String, String> entry : params.entrySet()) {
                Object actual = readParam(config, entry.getKey());
                assertNotNull(actual, descriptor.getTool() + "." + entry.getKey() + " did not bind");
                assertEquals(entry.getValue(), String.valueOf(actual),
                        descriptor.getTool() + "." + entry.getKey() + " did not bind");
            }
        }
    }

    @Test
    void blankValueKeepsTheBuilderDefault() {
        ShellToolConfig config = ToolConfigFactory.fromParams(ShellTool.Godzilla,
                Collections.singletonMap("pass", "  "));
        assertNotNull(config);
        assertFalse(readParam(config, "pass").toString().isEmpty(), "留空要走随机默认值");
    }

    @Test
    void generationParamsStayBindableWithoutBeingExposed() {
        ShellToolConfig config = ToolConfigFactory.fromParams(ShellTool.Godzilla,
                Collections.singletonMap("shellClassName", "com.example.Shell"));
        assertEquals("com.example.Shell", config.getShellClassName());
        assertFalse(namesOf(ShellTool.Godzilla).contains("shellClassName"), "生成期参数不进表单目录");
    }

    @Test
    void unknownParamIsRejectedWithTheSupportedNames() {
        GenerationException exception = assertThrows(GenerationException.class, () ->
                ToolConfigFactory.fromParams(ShellTool.Godzilla, Collections.singletonMap("godzillaPass", "x")));
        assertTrue(exception.getMessage().contains("godzillaPass"), exception.getMessage());
        assertTrue(exception.getMessage().contains("pass"), exception.getMessage());
    }

    /**
     * 工具没选/选了个没注册的名字时，要报「不支持的工具」而不是 ConcurrentHashMap 的 NPE
     * —— 界面上传的是自由文本（Dandelion 的 JMG 面板就是），错误得能显示给人看。
     */
    @Test
    void missingToolIsReportedNotThrownAsNpe() {
        GenerationException exception = assertThrows(GenerationException.class, () ->
                ToolConfigFactory.fromParams(null, Collections.singletonMap("pass", "x")));
        assertTrue(exception.getMessage().contains("Unsupported shell tool"), exception.getMessage());
        assertTrue(ToolConfigFactory.describeParams(null).isEmpty());
    }

    @Test
    void unsupportedEnumValueIsRejectedWithTheOptions() {
        GenerationException exception = assertThrows(GenerationException.class, () ->
                ToolConfigFactory.fromParams(ShellTool.Command, Collections.singletonMap("encryptor", "AES")));
        assertTrue(exception.getMessage().contains("AES"), exception.getMessage());
        assertTrue(exception.getMessage().contains("BASE64"), exception.getMessage());
    }

    private static String sampleValue(ToolConfigFactory.ConfigParam param) {
        return param.getOptions().isEmpty() ? "v_" + param.getName() : param.getOptions().get(0);
    }

    private static Object readParam(ShellToolConfig config, String name) {
        String suffix = Character.toUpperCase(name.charAt(0)) + name.substring(1);
        try {
            Method getter = config.getClass().getMethod("get" + suffix);
            return getter.invoke(config);
        } catch (Exception e) {
            throw new AssertionError("no getter for param " + name, e);
        }
    }

    private static List<String> namesOf(String tool) {
        List<String> names = new ArrayList<>();
        for (ToolConfigFactory.ConfigParam param : ToolConfigFactory.describeParams(tool)) {
            names.add(param.getName());
        }
        return names;
    }

    private static Map<String, ToolConfigFactory.ConfigParam> paramsOf(String tool) {
        Map<String, ToolConfigFactory.ConfigParam> params = new LinkedHashMap<>();
        for (ToolConfigFactory.ConfigParam param : ToolConfigFactory.describeParams(tool)) {
            params.put(param.getName(), param);
        }
        return params;
    }
}
