package com.reajason.javaweb.packer.jsp;

import com.reajason.javaweb.packer.ClassPackerConfig;
import com.reajason.javaweb.packer.Packer;
import com.reajason.javaweb.packer.Packers;

public class JspxUnicodePacker implements Packer {
    @Override
    public String pack(ClassPackerConfig classPackerConfig) {
        String content = Packers.JSPX.getInstance().pack(classPackerConfig);
        return JspUnicoder.encode(content, false);
    }
}
