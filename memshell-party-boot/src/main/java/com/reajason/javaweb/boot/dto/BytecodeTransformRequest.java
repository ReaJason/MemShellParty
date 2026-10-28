package com.reajason.javaweb.boot.dto;

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

    private String newClassName;
    private boolean randomName;
}
