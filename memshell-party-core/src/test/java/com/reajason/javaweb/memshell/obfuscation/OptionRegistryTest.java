package com.reajason.javaweb.memshell.obfuscation;

import com.reajason.javaweb.GenerationException;
import me.n1ar4.clazz.obfuscator.config.BaseConfig;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * OptionRegistry：解析、类型转换、范围校验、未知键校验、GUI key=value 文本解析。
 */
class OptionRegistryTest {

    @Test
    void shouldNormalizeBooleanFromString() {
        Map<String, Object> options = new LinkedHashMap<>();
        options.put("enableXOR", "false");
        options.put("enableAES", true);
        Map<String, Object> normalized = OptionRegistry.validateAndNormalize(options);
        assertEquals(Boolean.FALSE, normalized.get("enableXOR"));
        assertEquals(Boolean.TRUE, normalized.get("enableAES"));
    }

    @Test
    void shouldNormalizeIntegerFromString() {
        Map<String, Object> normalized = OptionRegistry.validateAndNormalize(
                Collections.singletonMap("expandParamNum", "4"));
        assertEquals(4, normalized.get("expandParamNum"));
    }

    @Test
    void shouldNormalizeListFromCommaSeparatedString() {
        Map<String, Object> normalized = OptionRegistry.validateAndNormalize(
                Collections.singletonMap("methodBlackList", "doFilter, service;init"));
        assertEquals(Arrays.asList("doFilter", "service", "init"), normalized.get("methodBlackList"));
    }

    @Test
    void shouldRejectUnknownKey() {
        GenerationException e = assertThrows(GenerationException.class, () ->
                OptionRegistry.validateAndNormalize(Collections.singletonMap("noSuchOption", true)));
        assertTrue(e.getMessage().contains("noSuchOption"));
    }

    @Test
    void shouldRejectFileBackedBadAnnoOptions() {
        // 这两个选项会读取调用方指定的本地文件，且 class-obf 在 static final 字段中跨请求缓存内容
        assertThrows(GenerationException.class, () ->
                OptionRegistry.validateAndNormalize(Collections.singletonMap("enableBadAnno", true)));
        assertThrows(GenerationException.class, () ->
                OptionRegistry.validateAndNormalize(Collections.singletonMap("badAnnoTextFile", "/etc/passwd")));
    }

    @Test
    void shouldRejectNullOptionValueWithClearError() {
        GenerationException e = assertThrows(GenerationException.class, () ->
                OptionRegistry.validateAndNormalize(Collections.singletonMap("expandParamNum", null)));
        assertTrue(e.getMessage().contains("expandParamNum"));
        assertTrue(e.getMessage().contains("Null"));
    }

    @Test
    void shouldRejectOutOfRangeValue() {
        assertThrows(GenerationException.class, () ->
                OptionRegistry.validateAndNormalize(Collections.singletonMap("expandParamNum", 101)));
        assertThrows(GenerationException.class, () ->
                OptionRegistry.validateAndNormalize(Collections.singletonMap("expandParamNum", -1)));
    }

    @Test
    void shouldRejectInvalidBoolean() {
        assertThrows(GenerationException.class, () ->
                OptionRegistry.validateAndNormalize(Collections.singletonMap("enableXOR", "maybe")));
    }

    @Test
    void shouldRejectDegenerateObfuscateChars() {
        // 去重后不足 3 个字符时 class-obf 名称空间耗尽，唯一名生成 while(true) 死循环且全程占住全局锁
        assertThrows(GenerationException.class, () ->
                OptionRegistry.validateAndNormalize(Collections.singletonMap("obfuscateChars", "i")));
        assertThrows(GenerationException.class, () ->
                OptionRegistry.validateAndNormalize(Collections.singletonMap("obfuscateChars", "i,i,i")));
        assertThrows(GenerationException.class, () ->
                OptionRegistry.validateAndNormalize(Collections.singletonMap("obfuscateChars", "i,l")));
        assertThrows(GenerationException.class, () ->
                OptionRegistry.validateAndNormalize(Collections.singletonMap("obfuscateChars", new String[]{"i", "i", "i"})));
        Map<String, Object> ok = OptionRegistry.validateAndNormalize(
                Collections.singletonMap("obfuscateChars", "i,l,L"));
        assertEquals(Arrays.asList("i", "l", "L"), ok.get("obfuscateChars"));
    }

    @Test
    void shouldValidateAesKeyByteLength() {
        // class-obf 以 key UTF-8 字节直接构造 SecretKeySpec，长度非法时其内部 catch 静默回退为明文输出
        assertThrows(GenerationException.class, () ->
                OptionRegistry.validateAndNormalize(Collections.singletonMap("aesKey", "abc")));
        assertThrows(GenerationException.class, () ->
                OptionRegistry.validateAndNormalize(Collections.singletonMap("aesKey", "")));
        Map<String, Object> ok = OptionRegistry.validateAndNormalize(
                Collections.singletonMap("aesKey", "1234567890123456"));
        assertEquals("1234567890123456", ok.get("aesKey"));
    }

    @Test
    void shouldApplyOptionsToBaseConfig() {
        BaseConfig config = new BaseConfig();
        Map<String, Object> options = new LinkedHashMap<>();
        options.put("enableXOR", false);
        options.put("expandParamNum", "5");
        options.put("methodBlackList", "keepMe,keepYou");
        OptionRegistry.apply(config, options);
        assertFalse(config.isEnableXOR());
        assertEquals(5, config.getExpandParamNum());
        assertArrayEquals(new String[]{"keepMe", "keepYou"}, config.getMethodBlackList());
    }

    @Test
    void shouldParseGuiKeyValueText() {
        String text = "# 注释行\n"
                + "enableXOR=false\n"
                + "expandParamNum=2\n"
                + "// 另一种注释\n"
                + "methodBlackList=doFilter,service\n";
        Map<String, Object> map = OptionRegistry.parseFromText(text);
        assertEquals(Boolean.FALSE, map.get("enableXOR"));
        assertEquals(2, map.get("expandParamNum"));
        assertEquals(Arrays.asList("doFilter", "service"), map.get("methodBlackList"));
    }

    @Test
    void shouldRejectMalformedGuiLine() {
        assertThrows(GenerationException.class, () -> OptionRegistry.parseFromText("noEqualsSign"));
        assertThrows(GenerationException.class, () -> OptionRegistry.parseFromText("unknownKey=1"));
    }

    @Test
    void shouldDescribeAllOptionsForCapabilities() {
        List<Map<String, Object>> all = OptionRegistry.describeAll();
        assertFalse(all.isEmpty());
        Map<String, Object> expandParamNum = all.stream()
                .filter(m -> "expandParamNum".equals(m.get("name")))
                .findFirst()
                .orElseThrow(AssertionError::new);
        assertEquals("integer", expandParamNum.get("type"));
        assertEquals(0, expandParamNum.get("min"));
        assertEquals(100, expandParamNum.get("max"));
        assertTrue(OptionRegistry.contains("methodBlackList"));
    }

    @Test
    void shouldReturnEmptyForNullOrEmpty() {
        assertTrue(OptionRegistry.validateAndNormalize(null).isEmpty());
        assertTrue(OptionRegistry.validateAndNormalize(Collections.emptyMap()).isEmpty());
        assertTrue(OptionRegistry.parseFromText(null).isEmpty());
        assertTrue(OptionRegistry.parseFromText("  \n ").isEmpty());
    }
}
