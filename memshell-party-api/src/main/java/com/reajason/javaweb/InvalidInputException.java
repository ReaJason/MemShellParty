package com.reajason.javaweb;

/**
 * 调用方入参不合法：缺字段、未知的 server / tool / type / param / packer / 混淆选项、
 * 非法 urlPattern 或 header 名、无法解析的 class 字节等。
 * <p>
 * 继承 {@link GenerationException}，GUI 和 SDK 里既有的 catch 行为不变；REST 层据此映射为
 * 400，真正的生成失败仍按 {@link GenerationException} 返回 500。
 *
 * @author ReaJason
 * @since 2026/10/31
 */
public class InvalidInputException extends GenerationException {
    public InvalidInputException(String message) {
        super(message);
    }

    public InvalidInputException(String message, Throwable cause) {
        super(message, cause);
    }
}
