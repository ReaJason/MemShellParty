package com.reajason.javaweb.memshell.config;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * 标注 {@link ShellToolConfig} 实现类里可由使用者配置的字段。
 * <p>
 * REST / MCP / 桌面端都按这个注解读出「有哪些参数、什么值类型、属于基础区还是高级区、叫什么名字」，
 * 字段的声明顺序就是表单里的顺序；没标注的字段（如生成期才写入的
 * {@code shellClassName} / {@code shellTemplateClassName}）不对外暴露。
 * <p>
 * 目前支持 {@code String} 与枚举两种字段类型：String 得到文本输入，枚举得到下拉框
 * （可选值即枚举常量名）。绑定时只接受标注过的字段名，写错名字会直接报错而不是静默忽略。
 *
 * @author ReaJason
 * @since 3.0.0
 */
@Documented
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.FIELD)
public @interface ConfigField {

    /**
     * 表单分组：基础字段直接铺开，高级字段收进「高级配置」。
     */
    Group group() default Group.BASIC;

    /**
     * 表单里的字段名，留空时用内置参数的中文名、再退回字段名本身。
     * <p>
     * 内置工具的参数名登记在界面里（{@code pass} → 密码），插件工具的参数名界面不认识，
     * 想显示中文就得自己写在这里。
     */
    String label() default "";

    /**
     * 输入框的占位提示，留空时用内置参数的提示、再退回「留空使用默认值」。
     * <p>
     * 语义只有工具自己知道（如密钥的位数要求），所以由工具声明而不是界面猜。
     */
    String placeholder() default "";

    enum Group {
        BASIC,
        ADVANCED
    }
}
