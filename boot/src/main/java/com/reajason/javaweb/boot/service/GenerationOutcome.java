package com.reajason.javaweb.boot.service;

import java.util.Map;

/**
 * 生成结果与打包结果的组合。
 * <p>
 * 类型参数容纳两种互不相关的生成结果：内存马的 {@code MemShellResult} 与探测马的
 * {@code ProbeShellResult}。二者同为 Lombok 数据类、无公共父类型，故用泛型而非继承抽象。
 * <p>
 * {@code packResult} 与 {@code allPackResults} 互斥：聚合打包器产出后者，单个打包器产出前者。
 *
 * @param <T> 生成结果类型
 * @author ReaJason
 */
public record GenerationOutcome<T>(T result, String packResult, Map<String, String> allPackResults) {

    public static <T> GenerationOutcome<T> ofSingle(T result, String packResult) {
        return new GenerationOutcome<>(result, packResult, null);
    }

    public static <T> GenerationOutcome<T> ofAggregate(T result, Map<String, String> allPackResults) {
        return new GenerationOutcome<>(result, null, allPackResults);
    }
}
