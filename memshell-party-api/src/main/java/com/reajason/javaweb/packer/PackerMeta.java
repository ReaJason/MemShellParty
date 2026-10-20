package com.reajason.javaweb.packer;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Repeatable;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * 打包器注册元数据。标在 {@link Packer} 实现类上，由 {@code PackerRegistry} 通过
 * {@code ServiceLoader} 发现后读取。
 *
 * <p>同一个实现类可以标多个 {@code @PackerMeta} 暴露多个注册名（例如
 * {@code JavaCommonsBeanutils17/18} 共用同一个实现）。
 *
 * <p>{@link #requiresClasses()} 是运行期可选依赖检查：任一 class 不存在时整个注册项跳过，
 * 用于“引入 packer 但排除 JNA/hessian/jackson 等依赖”的场景。检查只加载类、不初始化。
 *
 * @author ReaJason
 */
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.TYPE)
@Repeatable(PackerMetas.class)
@Documented
public @interface PackerMeta {

    /**
     * 稳定的注册名，用于 UI、REST/MCP 参数与结果展示；内置 packer 沿用旧枚举名。
     */
    String name();

    /**
     * 所属分组名，仅用于生成两级展示目录，不要求同名 packer 存在：
     * {@code parent = "Base64"} 即可把实现挂到 Base64 分类下。留空表示顶层。
     *
     * <p>分组只支持一级：不要把另一个已有 parent 的 packer 当作 parent。
     */
    String parent() default "";

    /**
     * 可选依赖：任一 class 在运行期不存在时跳过该注册项。用字符串而不是 Class，避免读取注解时
     * 就因缺失依赖抛 TypeNotPresentException。
     */
    String[] requiresClasses() default {};

    /**
     * 展示顺序，升序；同 order 按注册名排序。内置项按类别使用 100 起的递增 order，
     * 第三方默认 10000 排在末尾，需要插队时自行指定更小的值。
     */
    int order() default 10000;
}
