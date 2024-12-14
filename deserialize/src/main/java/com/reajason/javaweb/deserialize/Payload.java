package com.reajason.javaweb.deserialize;

/**
 * @author ReaJason
 * @since 2024/12/13
 */
public interface Payload {
    /**
     * 将恶意类字节流封装成序列化对象
     *
     * @param bytes 恶意类字节流
     * @return 序列化对象
     */
    Object generate(byte[] bytes);
}
