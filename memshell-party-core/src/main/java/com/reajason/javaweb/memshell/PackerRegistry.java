package com.reajason.javaweb.memshell;

import com.reajason.javaweb.InvalidInputException;
import com.reajason.javaweb.packer.ClassPackerConfig;
import com.reajason.javaweb.packer.JarPacker;
import com.reajason.javaweb.packer.JarPackerConfig;
import com.reajason.javaweb.packer.Packer;
import com.reajason.javaweb.packer.PackerCategory;
import com.reajason.javaweb.packer.PackerMeta;
import com.reajason.javaweb.packer.Packers;
import com.reajason.javaweb.probe.ProbeShellResult;

import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.ServiceLoader;

/**
 * 打包器 SPI 注册表：通过 {@link ServiceLoader} 发现 {@link Packer} 实现，按
 * {@link PackerMeta#parent()} 分组展示、过滤可选依赖并统一编排普通/Jar 两类产物。
 *
 * <p>分组只是展示目录：parent 是任意分组名，不要求同名 packer 存在；若同名 packer 存在，
 * 它仍然可以单独作为打包方式使用。没有聚合打包器，每个注册名都只产出一个 payload。
 *
 * <p>初始化不要求任何 packer 模块存在：没有 provider 时目录为空，生成链路直接输出 raw
 * Base64（见 {@link #RAW_LABEL}）。发现过程按条目防御：单个 packer 类加载/实例化失败
 * 只记录到 {@link #getLoadErrors()}，不会让整个目录失败。
 *
 * <p>同名单例与 {@link MemShellRegistry} 一致：插件宿主各自持有自己的类加载器副本。
 *
 * @author ReaJason
 */
public final class PackerRegistry {

    /**
     * 空打包方式：生成链路直接输出原始 Base64，不经过任何 packer。
     */
    public static final String RAW = "";

    /**
     * raw Base64 结果在 UI/响应中的展示名。
     */
    public static final String RAW_LABEL = Packers.Base64;

    private static final PackerRegistry INSTANCE = new PackerRegistry();

    private final Map<String, RegisteredPacker> packers = new LinkedHashMap<>();
    private final Map<String, List<String>> children = new LinkedHashMap<>();
    private final List<String> loadErrors = new ArrayList<>();
    private List<PackerCategory> tree = Collections.emptyList();
    private volatile boolean initialized = false;

    private PackerRegistry() {
    }

    public static PackerRegistry getInstance() {
        return INSTANCE;
    }

    /**
     * 测试用：清空并允许下次重新发现（例如切换 TCCL 后重新加载）。
     */
    public synchronized void reset() {
        packers.clear();
        children.clear();
        loadErrors.clear();
        tree = Collections.emptyList();
        initialized = false;
    }

    public synchronized void init() {
        if (initialized) {
            return;
        }
        // 先置位：init 内部不会再回调业务代码，但保持与 MemShellRegistry 相同的重入防御
        initialized = true;

        List<Candidate> discovered = new ArrayList<>();
        for (Packer packer : SpiLoader.load(Packer.class, loadErrors)) {
            collect(packer, discovered);
        }

        // ServiceLoader 先枚举父加载器的内置服务，再按 jar 文件名枚举插件服务。
        // 先去重再排序：内置与先加载插件始终优先，@PackerMeta.order 只决定展示顺序。
        Map<String, Class<?>> registeredNames = new HashMap<>();
        List<Candidate> candidates = new ArrayList<>();
        for (Candidate candidate : discovered) {
            if (isBlank(candidate.meta.name())) {
                loadErrors.add("Packer 注册名为空: " + candidate.packer.getClass().getName());
                continue;
            }
            if (!conditionsMet(candidate.meta, candidate.packer.getClass().getClassLoader())) {
                continue;
            }
            Class<?> existing = registeredNames.putIfAbsent(candidate.meta.name(), candidate.packer.getClass());
            if (existing != null) {
                loadErrors.add("Packer 重名: " + candidate.meta.name()
                        + " (" + existing.getName() + " / " + candidate.packer.getClass().getName()
                        + ")，保留先注册项");
                continue;
            }
            candidates.add(candidate);
        }

        // 稳定顺序：order 升序，再按注册名；重复项已在上面按发现顺序淘汰
        candidates.sort(Comparator
                .comparingInt((Candidate c) -> c.meta.order())
                .thenComparing(c -> c.meta.name()));
        for (Candidate candidate : candidates) {
            packers.put(candidate.meta.name(), new RegisteredPacker(candidate.packer, candidate.meta));
        }

        buildGroups();
        buildTree();
    }

    private void collect(Packer packer, List<Candidate> candidates) {
        PackerMeta[] metas;
        try {
            metas = packer.getClass().getAnnotationsByType(PackerMeta.class);
        } catch (Throwable t) {
            loadErrors.add("读取 @PackerMeta 失败: " + packer.getClass().getName() + ": " + message(t));
            return;
        }
        if (metas == null || metas.length == 0) {
            loadErrors.add("Packer 缺少 @PackerMeta: " + packer.getClass().getName());
            return;
        }
        for (PackerMeta meta : metas) {
            candidates.add(new Candidate(packer, meta));
        }
    }

    /**
     * 可选依赖检查：只加载不初始化，避免触发 packer 依赖的静态代码。
     */
    private static boolean conditionsMet(PackerMeta meta, ClassLoader loader) {
        for (String required : meta.requiresClasses()) {
            if (isBlank(required)) {
                continue;
            }
            try {
                Class.forName(required.trim(), false, loader);
            } catch (Throwable t) {
                return false;
            }
        }
        return true;
    }

    /**
     * 按 parent 字符串建立一级分组。parent 不需要指向已注册 packer，因此纯分组名也可以存在。
     */
    private void buildGroups() {
        for (Map.Entry<String, RegisteredPacker> entry : packers.entrySet()) {
            String name = entry.getKey();
            String parent = parentOf(entry.getValue().meta);
            if (parent == null) {
                continue;
            }
            if (parent.equals(name)) {
                loadErrors.add("Packer " + name + " 的 parent 不能指向自身");
                continue;
            }
            List<String> names = children.get(parent);
            if (names == null) {
                names = new ArrayList<>();
                children.put(parent, names);
            }
            names.add(name);
        }
    }

    private void buildTree() {
        // 顶层注册项 + 所有分组名（分组名可能没有对应 packer，如 Base64）
        LinkedHashSet<String> categoryNames = new LinkedHashSet<>();
        for (RegisteredPacker registered : packers.values()) {
            if (parentOf(registered.meta) == null) {
                categoryNames.add(registered.meta.name());
            }
        }
        categoryNames.addAll(children.keySet());

        List<String> ordered = new ArrayList<>(categoryNames);
        ordered.sort(categoryComparator());

        List<PackerCategory> categories = new ArrayList<>();
        for (String name : ordered) {
            List<String> childNames = children.get(name);
            if (childNames == null) {
                childNames = Collections.emptyList();
            } else {
                childNames = new ArrayList<>(childNames);
                childNames.sort(childComparator());
                RegisteredPacker registered = packers.get(name);
                if (registered != null && parentOf(registered.meta) != null) {
                    loadErrors.add("Packer " + name + " 既属于其他分组又包含子项，分组只支持一级");
                }
            }
            categories.add(new PackerCategory(name, childNames));
        }
        tree = Collections.unmodifiableList(categories);
    }

    /**
     * 分组排序：有同名 packer 时用它的 order；纯分组名用子项的最小 order。
     */
    private Comparator<String> categoryComparator() {
        return (a, b) -> {
            int byOrder = Integer.compare(categoryOrder(a), categoryOrder(b));
            return byOrder != 0 ? byOrder : a.compareTo(b);
        };
    }

    private int categoryOrder(String name) {
        RegisteredPacker registered = packers.get(name);
        if (registered != null) {
            return registered.meta.order();
        }
        int min = Integer.MAX_VALUE;
        List<String> names = children.get(name);
        if (names != null) {
            for (String child : names) {
                RegisteredPacker childPacker = packers.get(child);
                if (childPacker != null) {
                    min = Math.min(min, childPacker.meta.order());
                }
            }
        }
        return min;
    }

    private Comparator<String> childComparator() {
        return (a, b) -> {
            RegisteredPacker left = packers.get(a);
            RegisteredPacker right = packers.get(b);
            if (left == null || right == null) {
                return a.compareTo(b);
            }
            int byOrder = Integer.compare(left.meta.order(), right.meta.order());
            return byOrder != 0 ? byOrder : a.compareTo(b);
        };
    }

    public List<PackerCategory> getTree() {
        init();
        return tree;
    }

    public List<String> getNames() {
        init();
        return Collections.unmodifiableList(new ArrayList<>(packers.keySet()));
    }

    public boolean contains(String name) {
        init();
        return !isBlank(name) && packers.containsKey(name.trim());
    }

    /**
     * @throws IllegalArgumentException 名称为空或未注册
     */
    public Packer get(String name) {
        return require(name).packer;
    }

    public List<String> getChildren(String parentName) {
        init();
        List<String> names = children.get(parentName == null ? "" : parentName.trim());
        if (names == null) {
            return Collections.emptyList();
        }
        List<String> sorted = new ArrayList<>(names);
        sorted.sort(childComparator());
        return Collections.unmodifiableList(sorted);
    }

    public List<String> getLoadErrors() {
        init();
        return Collections.unmodifiableList(loadErrors);
    }

    /**
     * 内存马打包：空名称返回注入器字节的原始 Base64。
     */
    public String pack(String name, MemShellResult result) {
        init();
        if (isBlank(name)) {
            return result.getInjectorBytesBase64Str();
        }
        RegisteredPacker registered = require(name);
        if (registered.packer instanceof JarPacker) {
            byte[] bytes = ((JarPacker) registered.packer).packBytes(JarPackerConfig.from(result));
            return Base64.getEncoder().encodeToString(bytes);
        }
        return registered.packer.pack(result);
    }

    /**
     * 独立类打包：空名称返回类字节的原始 Base64，Jar 打包器只接收当前类。
     */
    public String pack(String name, ClassPackerConfig classConfig) {
        init();
        if (isBlank(name)) {
            return classConfig.getClassBytesBase64Str();
        }
        RegisteredPacker registered = require(name);
        if (registered.packer instanceof JarPacker) {
            byte[] bytes = ((JarPacker) registered.packer).packBytes(JarPackerConfig.from(classConfig));
            return Base64.getEncoder().encodeToString(bytes);
        }
        return registered.packer.pack(classConfig);
    }

    /**
     * 探测马打包：空名称返回探测马类字节的原始 Base64；探测马没有注入器，Jar 打包器不可用。
     */
    public String pack(String name, ProbeShellResult result) {
        init();
        if (isBlank(name)) {
            return result.getShellBytesBase64Str();
        }
        RegisteredPacker registered = require(name);
        if (registered.packer instanceof JarPacker) {
            throw new InvalidInputException("探测马不支持 Jar 打包: " + registered.meta.name());
        }
        ClassPackerConfig classConfig = ClassPackerConfig.of(result.getShellClassName(),
                result.getShellBytes(), result.getShellBytesBase64Str(),
                result.getProbeConfig() != null && result.getProbeConfig().needByPassJavaModule());
        return registered.packer.pack(classConfig);
    }

    private RegisteredPacker require(String name) {
        init();
        if (isBlank(name)) {
            throw new IllegalArgumentException("打包方式为空");
        }
        RegisteredPacker registered = packers.get(name.trim());
        if (registered == null) {
            throw new IllegalArgumentException("未知打包方式: " + name);
        }
        return registered;
    }

    private static String parentOf(PackerMeta meta) {
        String parent = meta.parent();
        return isBlank(parent) ? null : parent.trim();
    }

    private static boolean isBlank(String value) {
        return value == null || value.trim().isEmpty();
    }

    private static String message(Throwable t) {
        return SpiLoader.message(t);
    }

    private static final class Candidate {
        private final Packer packer;
        private final PackerMeta meta;

        private Candidate(Packer packer, PackerMeta meta) {
            this.packer = packer;
            this.meta = meta;
        }
    }

    private static final class RegisteredPacker {
        private final Packer packer;
        private final PackerMeta meta;

        private RegisteredPacker(Packer packer, PackerMeta meta) {
            this.packer = packer;
            this.meta = meta;
        }
    }
}
