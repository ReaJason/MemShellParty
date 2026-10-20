package com.reajason.javaweb.packer;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * {@link PackerMeta} 的容器注解，支持同一实现类声明多个注册名。
 *
 * @author ReaJason
 */
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.TYPE)
@Documented
public @interface PackerMetas {
    PackerMeta[] value();
}
