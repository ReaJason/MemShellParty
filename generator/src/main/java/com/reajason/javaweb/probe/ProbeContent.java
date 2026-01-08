package com.reajason.javaweb.probe;

/**
 * @author ReaJason
 * @since 2025/6/30
 */
public enum ProbeContent {
    Server,
    OS,
    JDK,
    // 字节码执行
    Bytecode,
    // 命令执行
    Command,
    // 基础信息
    BasicInfo,
    // 脚本引擎执行
    ScriptEngine,
    // Filter 配置
    Filter
}
