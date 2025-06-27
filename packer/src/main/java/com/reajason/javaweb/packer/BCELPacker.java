package com.reajason.javaweb.packer;

import lombok.SneakyThrows;
import org.apache.bcel.classfile.Utility;

/**
 * @author ReaJason
 * @since 2024/12/19
 */
public class BCELPacker implements Packer {
    @Override
    @SneakyThrows
    public String pack(ClassPackerConfig config) {
        return "$$BCEL$$" + Utility.encode(config.getClassBytes(), true);
    }
}
