package com.reajason.javaweb;

/**
 * @author ReaJason
 * @since 2025/7/21
 */
public class GenerationException extends RuntimeException {
    public GenerationException(String message) {
        super(message);
    }

    public GenerationException(String message, Throwable cause) {
        super(message, cause);
    }
}
