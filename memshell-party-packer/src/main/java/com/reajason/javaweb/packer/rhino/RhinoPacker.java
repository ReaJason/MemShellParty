package com.reajason.javaweb.packer.rhino;

import com.reajason.javaweb.packer.ClassPackerConfig;
import com.reajason.javaweb.packer.Packer;
import com.reajason.javaweb.packer.PackerMeta;
import com.reajason.javaweb.packer.Packers;
import com.reajason.javaweb.packer.scriptengine.ScriptEnginePacker;
import org.kohsuke.MetaInfServices;

/**
 * @author ReaJason
 * @since 2025/1/30
 */
@MetaInfServices(Packer.class)
@PackerMeta(name = Packers.Rhino, order = 700)
public class RhinoPacker implements Packer {

    @Override
    public String pack(ClassPackerConfig config) {
        return new ScriptEnginePacker().pack(config);
    }
}
