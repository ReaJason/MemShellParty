package com.reajason.javaweb.packer.jsp;

import com.reajason.javaweb.packer.ClassPackerConfig;
import com.reajason.javaweb.packer.Packer;
import com.reajason.javaweb.packer.PackerMeta;
import com.reajason.javaweb.packer.Packers;
import org.kohsuke.MetaInfServices;

@MetaInfServices(Packer.class)
@PackerMeta(name = Packers.JSPXUnicode, parent = Packers.JSP, order = 260)
public class JspxUnicodePacker implements Packer {
    @Override
    public String pack(ClassPackerConfig classPackerConfig) {
        String content = new JspxPacker().pack(classPackerConfig);
        return JspUnicoder.encode(content, false);
    }
}
