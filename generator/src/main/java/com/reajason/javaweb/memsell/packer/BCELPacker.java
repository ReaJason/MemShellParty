package com.reajason.javaweb.memsell.packer;

import com.reajason.javaweb.config.GenerateResult;
import lombok.SneakyThrows;
import org.apache.bcel.classfile.Utility;

/**
 * @author ReaJason
 * @since 2024/12/19
 */
public class BCELPacker implements Packer {
    @Override
    @SneakyThrows
    public String pack(GenerateResult generateResult) {
        return "$$BCEL$$" + Utility.encode(generateResult.getInjectorBytes(), true);
    }
}