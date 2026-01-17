package com.reajason.javaweb.packer.jsp;

import com.reajason.javaweb.packer.ClassPackerConfig;
import com.reajason.javaweb.packer.Packer;
import com.reajason.javaweb.packer.Packers;
import com.reajason.javaweb.packer.Util;
import lombok.SneakyThrows;

/**
 * @author ReaJason
 * @since 2024/11/26
 */
public class DefineClassJspUnicodePacker implements Packer {

    @Override
    @SneakyThrows
    public String pack(ClassPackerConfig config) {
        return JspUnicoder.encode(Packers.DefineClassJSP.getInstance().pack(config), true);
    }
}