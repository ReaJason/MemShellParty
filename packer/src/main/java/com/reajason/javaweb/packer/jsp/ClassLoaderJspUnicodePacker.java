package com.reajason.javaweb.packer.jsp;

import com.reajason.javaweb.packer.ClassPackerConfig;
import com.reajason.javaweb.packer.Packer;
import com.reajason.javaweb.packer.Packers;

public class ClassLoaderJspUnicodePacker implements Packer {
    @Override
    public String pack(ClassPackerConfig classPackerConfig) {
        return JspUnicoder.encode(Packers.ClassLoaderJSP.getInstance().pack(classPackerConfig), true);
    }
}
