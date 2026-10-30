package com.reajason.javaweb.boot.service;

import com.reajason.javaweb.boot.dto.BytecodeClassResponse;
import com.reajason.javaweb.boot.dto.BytecodeTransformRequest;
import com.reajason.javaweb.boot.dto.BytecodeTransformResponse;
import com.reajason.javaweb.bytecode.BytecodeToolService;
import com.reajason.javaweb.bytecode.ClassBytesDecoder;
import com.reajason.javaweb.memshell.PackerRegistry;
import com.reajason.javaweb.packer.ClassPackerConfig;
import org.springframework.stereotype.Service;

import java.util.Base64;

@Service
public class BytecodeTransformService {
    private static final int MAX_ENCODED_INPUT_CHARS = ClassBytesDecoder.MAX_CLASS_BYTES * 2;

    private final ClassBytesDecoder decoder = new ClassBytesDecoder();
    private final BytecodeToolService toolService = new BytecodeToolService();

    public BytecodeClassResponse decode(String base64Text) {
        ClassBytesDecoder.DecodedClass decoded = decodeClass(base64Text);
        return new BytecodeClassResponse(decoded.getClassName(), decoded.getClassBytes().length,
                Base64.getEncoder().encodeToString(decoded.getClassBytes()));
    }

    public BytecodeTransformResponse transform(BytecodeTransformRequest request) {
        if (request == null) {
            throw new IllegalArgumentException("请求不能为空");
        }
        ClassBytesDecoder.DecodedClass input = decodeClass(request.getClassBytesBase64());
        BytecodeToolService.TransformResult result = applyTools(input.getClassBytes(), request);
        String classBase64 = Base64.getEncoder().encodeToString(result.getClassBytes());
        ClassPackerConfig packerConfig = ClassPackerConfig.of(result.getClassName(), result.getClassBytes(),
                classBase64, request.isByPassJavaModule());
        String packer = request.getPacker() == null ? "" : request.getPacker().trim();
        String packResult = PackerRegistry.getInstance().pack(packer, packerConfig);
        return new BytecodeTransformResponse(result.getClassName(), result.getSize(), classBase64, packResult);
    }

    private ClassBytesDecoder.DecodedClass decodeClass(String base64Text) {
        if (base64Text != null && base64Text.length() > MAX_ENCODED_INPUT_CHARS) {
            throw new IllegalArgumentException("编码输入过大，解压后的类字节上限为 "
                    + ClassBytesDecoder.MAX_CLASS_BYTES / 1024 / 1024 + " MB");
        }
        return decoder.decodeBase64(base64Text);
    }

    private BytecodeToolService.TransformResult applyTools(byte[] classBytes, BytecodeTransformRequest request) {
        String relocateFrom = null;
        String relocateTo = null;
        if (request.isRenamePackage()) {
            relocateFrom = request.getRelocateFrom();
            relocateTo = request.getRelocateTo();
            if (relocateFrom == null || relocateFrom.trim().isEmpty()
                    || relocateTo == null || relocateTo.trim().isEmpty()) {
                throw new IllegalArgumentException("包名重命名需要同时填写原包名前缀与新包名前缀");
            }
        }

        BytecodeToolService.TransformResult result = toolService.convert(classBytes);
        if (request.isByPassJavaModule()) {
            result = toolService.addModuleBypass(result.getClassBytes());
        }
        if (request.isStaticInitialize()) {
            result = toolService.addStaticTrigger(result.getClassBytes(),
                    BytecodeToolService.TriggerMode.CONSTRUCTOR,
                    BytecodeToolService.ConstructorMode.AUTO, null);
        }
        result = toolService.renameAndShrink(result.getClassBytes(), request.getNewClassName(), null,
                request.isRandomName(), request.isShrink());
        if (relocateFrom != null) {
            result = toolService.changeClassInfo(result.getClassBytes(), null, relocateFrom, relocateTo);
        }
        if (request.getEntryMethod() != null && !request.getEntryMethod().trim().isEmpty()) {
            result = toolService.addEntryMethod(result.getClassBytes(), request.getEntryMethod());
        }
        return result;
    }
}
