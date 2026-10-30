package com.reajason.javaweb.examples.plugin;

import com.reajason.javaweb.packer.ClassPackerConfig;
import com.reajason.javaweb.packer.Packer;
import com.reajason.javaweb.packer.PackerMeta;
import com.reajason.javaweb.packer.Packers;
import org.kohsuke.MetaInfServices;

import java.util.Base64;

@MetaInfServices(Packer.class)
@PackerMeta(name = ExamplePacker.NAME, parent = Packers.Base64)
public class ExamplePacker implements Packer {
    public static final String NAME = "ExampleBase64URL";

    @Override
    public String pack(ClassPackerConfig config) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(config.getClassBytes());
    }
}
