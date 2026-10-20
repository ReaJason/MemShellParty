package com.reajason.javaweb.packer.jsp;

import com.reajason.javaweb.packer.ClassPackerConfig;
import com.reajason.javaweb.packer.Packer;
import com.reajason.javaweb.packer.PackerMeta;
import com.reajason.javaweb.packer.Packers;
import org.kohsuke.MetaInfServices;

@MetaInfServices(Packer.class)
@PackerMeta(name = Packers.ClassLoaderJSPUnicode, parent = Packers.JSP, order = 220)
public class ClassLoaderJspUnicodePacker implements Packer {
    @Override
    public String pack(ClassPackerConfig classPackerConfig) {
        return JspUnicoder.encode(new ClassLoaderJspPacker().pack(classPackerConfig), true);
    }
}
