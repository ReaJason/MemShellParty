package com.reajason.javaweb.packer;

import com.reajason.javaweb.memshell.MemShellResult;
import com.reajason.javaweb.utils.NameSampler;

/**
 * 打包器契约：把生成器产出的类字节转成最终投递载荷。
 *
 * <p>实现类通过 {@link PackerMeta} 声明注册名、所属分组与可选依赖；通过
 * {@code META-INF/services/com.reajason.javaweb.packer.Packer} 暴露给
 * {@code PackerRegistry} 发现。实现必须是 public、非抽象、带 public 无参构造，
 * 且构造/类初始化阶段不能触碰 {@link PackerMeta#requiresClasses()} 之外的可选依赖 ——
 * ServiceLoader 会先实例化，再由注册表按条件过滤。
 *
 * @author ReaJason
 */
public interface Packer {

    /**
     * SpringGzipJDK17 系打包器通过 cglib 定义类时以
     * {@code org.springframework.expression.ExpressionParser} 作为保护域，
     * 注入器/探测类必须位于 {@code org.springframework.expression} 包下。
     */
    default boolean requiresSpringExpressionPackage() {
        return false;
    }

    /**
     * 载荷最终会作为 SpEL 表达式交给 Spring 解析（{@code SpELSpringGzip} 系直接就是表达式，
     * {@code SpELScriptEngine} 是外包一层 SpEL、{@code FreemarkerSpEL*} 是模板内嵌表达式）。
     * {@code InternalSpelExpressionParser} 限制表达式长度为 10000 字符，而混淆后的注入器
     * 通常在 15KB 左右，因此这类 packer 生成时应关闭混淆。
     */
    default boolean transportedAsSpelExpression() {
        return false;
    }

    /**
     * 为 SpringGzipJDK17 系打包器生成类名：包名固定，简单名由 {@link NameSampler} 采样。
     */
    default String generateSpringExpressionClassName() {
        if (!requiresSpringExpressionPackage()) {
            throw new IllegalStateException(getClass().getName() + " 不要求 org.springframework.expression 包");
        }
        return "org.springframework.expression." + NameSampler.sample("Utils").getSimpleName();
    }

    /**
     * 将自定义类打包成特定 payload。
     *
     * @param classPackerConfig 自定义类信息
     * @return 字符串 payload
     */
    default String pack(ClassPackerConfig classPackerConfig) {
        throw new UnsupportedOperationException("当前 " + getClass().getSimpleName()
                + " 需要完整的内存马生成结果，不支持独立 class 打包");
    }

    /**
     * 将完整生成结果打包成最终投递载荷。需要 shell、injector 及其辅助类的打包器覆盖此方法；
     * 普通打包器继续沿用到 {@link #pack(ClassPackerConfig)} 的默认委托。
     */
    default String pack(MemShellResult result) {
        return pack(ClassPackerConfig.from(result));
    }
}
