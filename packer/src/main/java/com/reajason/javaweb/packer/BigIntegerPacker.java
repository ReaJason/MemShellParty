package com.reajason.javaweb.packer;

import lombok.SneakyThrows;

import java.math.BigInteger;

/**
 * @author Wans
 * @since 2025/08/26
 */
public class BigIntegerPacker implements Packer {
    @Override
    @SneakyThrows
    public String pack(ClassPackerConfig config) {
        return new BigInteger(config.getClassBytes()).toString( Character.MAX_RADIX);
    }
}
