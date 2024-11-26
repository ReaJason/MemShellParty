package com.reajason.javaweb.memsell.packer;

import com.reajason.javaweb.config.GenerateResult;

/**
 * @author ReaJason
 * @since 2024/11/26
 */
public interface Packer {
    byte[] pack(GenerateResult generateResult);
}
