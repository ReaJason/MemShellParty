package com.reajason.javaweb.memshell.obfuscation;

import com.reajason.javaweb.GenerationException;
import me.n1ar4.clazz.obfuscator.config.BaseConfig;

import java.nio.charset.StandardCharsets;
import java.util.*;

/**
 * 集中选项注册表：管理 class-obf 混淆参数的元数据、类型转换、范围校验与未知键校验。
 *
 * @author ReaJason
 */
public final class OptionRegistry {

    public enum OptionType {
        BOOLEAN,
        INTEGER,
        STRING,
        LIST
    }

    public static final class OptionMeta {
        private final String name;
        private final OptionType type;
        private final Object defaultValue;
        private final String description;
        private final Integer min;
        private final Integer max;

        public OptionMeta(String name, OptionType type, Object defaultValue, String description) {
            this(name, type, defaultValue, description, null, null);
        }

        public OptionMeta(String name, OptionType type, Object defaultValue, String description, Integer min, Integer max) {
            this.name = name;
            this.type = type;
            this.defaultValue = defaultValue;
            this.description = description;
            this.min = min;
            this.max = max;
        }

        public String getName() {
            return name;
        }

        public OptionType getType() {
            return type;
        }

        public Object getDefaultValue() {
            return defaultValue;
        }

        public String getDescription() {
            return description;
        }

        public Integer getMin() {
            return min;
        }

        public Integer getMax() {
            return max;
        }

        public Map<String, Object> toMap() {
            Map<String, Object> map = new LinkedHashMap<>();
            map.put("name", name);
            map.put("type", type.name().toLowerCase(Locale.ROOT));
            map.put("defaultValue", defaultValue);
            map.put("description", description);
            if (min != null) {
                map.put("min", min);
            }
            if (max != null) {
                map.put("max", max);
            }
            return map;
        }
    }

    private static final Map<String, OptionMeta> OPTIONS = new LinkedHashMap<>();

    static {
        register(new OptionMeta("enableDeleteCompileInfo", OptionType.BOOLEAN, true, "Remove compilation info (source file name, line numbers, etc.)"));
        register(new OptionMeta("enableAES", OptionType.BOOLEAN, true, "Encrypt string constants using AES"));
        register(new OptionMeta("enableAdvanceString", OptionType.BOOLEAN, true, "Enable AdvanceString pre-decryption optimization"));
        register(new OptionMeta("enableXOR", OptionType.BOOLEAN, true, "Obfuscate integer constants using XOR expressions"));
        register(new OptionMeta("enableFieldName", OptionType.BOOLEAN, true, "Obfuscate field names"));
        register(new OptionMeta("enableMethodName", OptionType.BOOLEAN, true, "Obfuscate method names"));
        register(new OptionMeta("enableParamName", OptionType.BOOLEAN, true, "Obfuscate method parameter names"));
        register(new OptionMeta("enableShuffleMember", OptionType.BOOLEAN, true, "Shuffle order of class members"));
        register(new OptionMeta("enableControlFlow", OptionType.BOOLEAN, true, "Flatten and obfuscate method control flow"));
        register(new OptionMeta("autoDisableImpl", OptionType.BOOLEAN, true, "Automatically detect and preserve interface implementation methods"));
        register(new OptionMeta("ignorePublic", OptionType.BOOLEAN, false, "Skip obfuscating public methods"));
        register(new OptionMeta("asmAutoCompute", OptionType.BOOLEAN, true, "Automatically recompute stack frames and local variable table sizes"));
        register(new OptionMeta("quiet", OptionType.BOOLEAN, true, "Quiet mode, suppress class-obf console output"));
        register(new OptionMeta("methodBlackList", OptionType.LIST, Collections.emptyList(), "Blacklist of method names that must not be renamed"));

        register(new OptionMeta("enableHideField", OptionType.BOOLEAN, false, "Hide field metadata features"));
        register(new OptionMeta("enableHideMethod", OptionType.BOOLEAN, false, "Hide method metadata features"));
        register(new OptionMeta("useEvilCharInstead", OptionType.BOOLEAN, false, "Use invisible characters for renamed identifiers"));
        // 注意：enableBadAnno/badAnnoTextFile 会读取调用方指定的本地文件，且 class-obf 将内容
        // 缓存在 static final 字段中（每 JVM 只读取一次）。暴露给 REST/MCP 会形成任意文件读取
        // 与跨请求内容泄漏，因此不注册这两个选项。
        register(new OptionMeta("antiAI", OptionType.BOOLEAN, false, "Anti-AI decompilation and reverse engineering heuristics"));
        register(new OptionMeta("enableInvokeDynamic", OptionType.BOOLEAN, false, "Hide method calls using invokedynamic instructions"));
        register(new OptionMeta("enableImageCrash", OptionType.BOOLEAN, false, "Inject corrupted image resources to crash decompilers"));
        register(new OptionMeta("enableTrim", OptionType.BOOLEAN, false, "Strip unused attributes"));
        register(new OptionMeta("enableExpandMethod", OptionType.BOOLEAN, false, "Expand method parameter lists with dummy arguments"));
        register(new OptionMeta("expandParamNum", OptionType.INTEGER, 0, "Number of dummy parameters to append when expanding methods (0-100)", 0, 100));
        register(new OptionMeta("expandMethodList", OptionType.LIST, Collections.emptyList(), "List of method names to apply parameter expansion to"));
        register(new OptionMeta("obfuscateChars", OptionType.LIST, Arrays.asList("i", "l", "L", "1", "I"), "Character set used for generating obfuscated identifiers (at least 3 distinct entries required)"));
        register(new OptionMeta("logLevel", OptionType.STRING, "info", "Logging level (debug/info/warn/error)"));
        register(new OptionMeta("aesKey", OptionType.STRING, null, "AES key for string encryption (UTF-8 byte length must be 16/24/32)"));
        register(new OptionMeta("aesDecName", OptionType.STRING, null, "Method name for the AES decryption routine"));
        register(new OptionMeta("aesKeyField", OptionType.STRING, null, "Field name storing the AES encryption key"));
        register(new OptionMeta("advanceStringName", OptionType.STRING, null, "Array field name for AdvanceString decryption"));
    }

    private static void register(OptionMeta meta) {
        OPTIONS.put(meta.getName(), meta);
    }

    private OptionRegistry() {
    }

    public static boolean contains(String name) {
        return OPTIONS.containsKey(name);
    }

    public static OptionMeta get(String name) {
        return OPTIONS.get(name);
    }

    public static List<Map<String, Object>> describeAll() {
        List<Map<String, Object>> list = new ArrayList<>();
        for (OptionMeta meta : OPTIONS.values()) {
            list.add(meta.toMap());
        }
        return Collections.unmodifiableList(list);
    }

    /**
     * 解析并校验 options Map，校验未知键与值类型/范围。
     */
    public static Map<String, Object> validateAndNormalize(Map<String, ?> options) {
        if (options == null || options.isEmpty()) {
            return new LinkedHashMap<>();
        }
        Map<String, Object> normalized = new LinkedHashMap<>();
        for (Map.Entry<String, ?> entry : options.entrySet()) {
            String key = entry.getKey();
            Object rawValue = entry.getValue();
            OptionMeta meta = OPTIONS.get(key);
            if (meta == null) {
                throw new GenerationException("Unknown obfuscation option: " + key);
            }
            normalized.put(key, convertAndValidate(meta, rawValue));
        }
        return normalized;
    }

    /**
     * 将 options 应用到 BaseConfig 上。
     */
    public static void apply(BaseConfig config, Map<String, ?> options) {
        Map<String, Object> normalized = validateAndNormalize(options);
        for (Map.Entry<String, Object> entry : normalized.entrySet()) {
            applyField(config, entry.getKey(), entry.getValue());
        }
    }

    /**
     * 解析 GUI 多行文本为 options Map (key=value 格式)。
     */
    public static Map<String, Object> parseFromText(String text) {
        if (text == null || text.trim().isEmpty()) {
            return new LinkedHashMap<>();
        }
        Map<String, Object> map = new LinkedHashMap<>();
        String[] lines = text.split("\\r?\\n");
        for (String line : lines) {
            String trimmed = line.trim();
            if (trimmed.isEmpty() || trimmed.startsWith("#") || trimmed.startsWith("//")) {
                continue;
            }
            int eqIdx = trimmed.indexOf('=');
            if (eqIdx <= 0) {
                throw new GenerationException("Invalid option line (expected key=value): " + trimmed);
            }
            String key = trimmed.substring(0, eqIdx).trim();
            String val = trimmed.substring(eqIdx + 1).trim();
            OptionMeta meta = OPTIONS.get(key);
            if (meta == null) {
                throw new GenerationException("Unknown obfuscation option: " + key);
            }
            map.put(key, convertAndValidate(meta, val));
        }
        return map;
    }

    private static Object convertAndValidate(OptionMeta meta, Object rawValue) {
        String key = meta.getName();
        if (rawValue == null) {
            throw new GenerationException("Null value for obfuscation option '" + key + "'");
        }
        switch (meta.getType()) {
            case BOOLEAN:
                if (rawValue instanceof Boolean) {
                    return rawValue;
                }
                String sBool = String.valueOf(rawValue).trim();
                if ("true".equalsIgnoreCase(sBool)) {
                    return Boolean.TRUE;
                }
                if ("false".equalsIgnoreCase(sBool)) {
                    return Boolean.FALSE;
                }
                throw new GenerationException("Invalid boolean value for option '" + key + "': " + rawValue);
            case INTEGER:
                int intVal;
                if (rawValue instanceof Number) {
                    intVal = ((Number) rawValue).intValue();
                } else {
                    try {
                        intVal = Integer.parseInt(String.valueOf(rawValue).trim());
                    } catch (NumberFormatException e) {
                        throw new GenerationException("Invalid integer value for option '" + key + "': " + rawValue);
                    }
                }
                if (meta.getMin() != null && intVal < meta.getMin()) {
                    throw new GenerationException("Option '" + key + "' value " + intVal + " must be >= " + meta.getMin());
                }
                if (meta.getMax() != null && intVal > meta.getMax()) {
                    throw new GenerationException("Option '" + key + "' value " + intVal + " must be <= " + meta.getMax());
                }
                return intVal;
            case STRING:
                String strVal = String.valueOf(rawValue);
                if ("aesKey".equals(key)) {
                    validateAesKey(strVal);
                }
                return strVal;
            case LIST:
                List<String> listVal;
                if (rawValue instanceof String[]) {
                    listVal = Arrays.asList((String[]) rawValue);
                } else if (rawValue instanceof Collection<?>) {
                    listVal = new ArrayList<>();
                    for (Object item : (Collection<?>) rawValue) {
                        if (item != null) {
                            String s = String.valueOf(item).trim();
                            if (!s.isEmpty()) {
                                listVal.add(s);
                            }
                        }
                    }
                } else {
                    String str = String.valueOf(rawValue).trim();
                    listVal = new ArrayList<>();
                    for (String part : str.split("[,;]")) {
                        String trimmed = part.trim();
                        if (!trimmed.isEmpty()) {
                            listVal.add(trimmed);
                        }
                    }
                }
                if ("obfuscateChars".equals(key)) {
                    validateObfuscateChars(listVal);
                }
                return listVal;
            default:
                return rawValue;
        }
    }

    /**
     * class-obf 的 NameUtil 从字符池随机拼接 10~12 位标识符并 while(true) 查重，去重后可用字符
     * 太少时名称空间迅速耗尽、生成循环永不退出，而混淆全程持有 JVM 全局锁与跨进程文件锁，
     * 会把后续所有混淆请求一起挂死。默认池为 5 个字符，这里要求去重后至少 3 个。
     */
    private static void validateObfuscateChars(List<String> chars) {
        long distinct = chars.stream().distinct().count();
        if (distinct < 3) {
            throw new GenerationException("Option 'obfuscateChars' requires at least 3 distinct entries, got "
                    + distinct + ": " + chars);
        }
    }

    /**
     * class-obf 以 key.getBytes("UTF-8") 直接构造 SecretKeySpec("AES")，且字符串加密流程把异常
     * catch 后静默回退为明文输出；密钥长度不合法时产物字符串不加密但无任何报错，这里按 AES
     * 密钥规格（16/24/32 字节）前置拦截。
     */
    private static void validateAesKey(String key) {
        int bytes = key.getBytes(StandardCharsets.UTF_8).length;
        if (bytes != 16 && bytes != 24 && bytes != 32) {
            throw new GenerationException("Option 'aesKey' must be 16/24/32 bytes in UTF-8, got " + bytes);
        }
    }

    private static void applyField(BaseConfig config, String key, Object val) {
        switch (key) {
            case "enableDeleteCompileInfo":
                config.setEnableDeleteCompileInfo((Boolean) val);
                break;
            case "enableAES":
                config.setEnableAES((Boolean) val);
                break;
            case "enableAdvanceString":
                config.setEnableAdvanceString((Boolean) val);
                break;
            case "enableXOR":
                config.setEnableXOR((Boolean) val);
                break;
            case "enableFieldName":
                config.setEnableFieldName((Boolean) val);
                break;
            case "enableMethodName":
                config.setEnableMethodName((Boolean) val);
                break;
            case "enableParamName":
                config.setEnableParamName((Boolean) val);
                break;
            case "enableShuffleMember":
                config.setEnableShuffleMember((Boolean) val);
                break;
            case "enableControlFlow":
                config.setEnableControlFlow((Boolean) val);
                break;
            case "autoDisableImpl":
                config.setAutoDisableImpl((Boolean) val);
                break;
            case "ignorePublic":
                config.setIgnorePublic((Boolean) val);
                break;
            case "asmAutoCompute":
                config.setAsmAutoCompute((Boolean) val);
                break;
            case "quiet":
                config.setQuiet((Boolean) val);
                break;
            case "methodBlackList":
                @SuppressWarnings("unchecked")
                List<String> bl = (List<String>) val;
                config.setMethodBlackList(bl.toArray(new String[0]));
                break;
            case "enableHideField":
                config.setEnableHideField((Boolean) val);
                break;
            case "enableHideMethod":
                config.setEnableHideMethod((Boolean) val);
                break;
            case "useEvilCharInstead":
                config.setUseEvilCharInstead((Boolean) val);
                break;
            case "antiAI":
                config.setAntiAI((Boolean) val);
                break;
            case "enableInvokeDynamic":
                config.setEnableInvokeDynamic((Boolean) val);
                break;
            case "enableImageCrash":
                config.setEnableImageCrash((Boolean) val);
                break;
            case "enableTrim":
                config.setEnableTrim((Boolean) val);
                break;
            case "enableExpandMethod":
                config.setEnableExpandMethod((Boolean) val);
                break;
            case "expandParamNum":
                config.setExpandParamNum((Integer) val);
                break;
            case "expandMethodList":
                @SuppressWarnings("unchecked")
                List<String> eml = (List<String>) val;
                config.setExpandMethodList(eml.toArray(new String[0]));
                break;
            case "obfuscateChars":
                @SuppressWarnings("unchecked")
                List<String> oc = (List<String>) val;
                config.setObfuscateChars(oc.toArray(new String[0]));
                break;
            case "logLevel":
                config.setLogLevel((String) val);
                break;
            case "aesKey":
                config.setAesKey((String) val);
                break;
            case "aesDecName":
                config.setAesDecName((String) val);
                break;
            case "aesKeyField":
                config.setAesKeyField((String) val);
                break;
            case "advanceStringName":
                config.setAdvanceStringName((String) val);
                break;
            default:
                break;
        }
    }
}
