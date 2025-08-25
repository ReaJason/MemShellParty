package com.reajason.javaweb.packer;

import lombok.SneakyThrows;

import java.math.BigInteger;

public class BigIntegerPacker implements Packer {
    @Override
    @SneakyThrows
    public String pack(ClassPackerConfig config) {
        return new BigInteger(config.getClassBytes()).toString(36);
    }
}
