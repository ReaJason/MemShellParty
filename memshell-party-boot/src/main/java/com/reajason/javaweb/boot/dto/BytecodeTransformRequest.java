package com.reajason.javaweb.boot.dto;

import com.reajason.javaweb.memshell.config.ObfuscationConfig;
import com.reajason.javaweb.probe.config.ProbeConfig;
import lombok.Data;

@Data
public class BytecodeTransformRequest {
    private String classBytesBase64;
    private String packer;
    private boolean byPassJavaModule;
    private boolean staticInitialize;
    private boolean shrink = true;

    private boolean renamePackage;
    private String relocateFrom;
    private String relocateTo;
    private String entryMethod;

    private String newClassName;
    private boolean randomName;
    private ObfuscationConfig obfuscation;

    private String server;
    private ProbeConfig probe;
}
