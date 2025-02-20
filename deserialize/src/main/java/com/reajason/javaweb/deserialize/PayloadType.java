package com.reajason.javaweb.deserialize;

import com.reajason.javaweb.deserialize.payload.hessian.XSLTScriptEngine;
import com.reajason.javaweb.deserialize.payload.java.CommonsBeanutils110;
import com.reajason.javaweb.deserialize.payload.java.CommonsBeanutils16;
import com.reajason.javaweb.deserialize.payload.java.CommonsBeanutils18;
import com.reajason.javaweb.deserialize.payload.java.CommonsBeanutils19;
import lombok.Getter;

/**
 * @author ReaJason
 * @since 2024/12/13
 */
@Getter
public enum PayloadType {
    /**
     * CB 链
     */
    CommonsBeanutils16(new CommonsBeanutils16()),
    CommonsBeanutils18(new CommonsBeanutils18()),
    CommonsBeanutils19(new CommonsBeanutils19()),
    CommonsBeanutils110(new CommonsBeanutils110()),

    /**
     * Hessian XSLT write
     */
    XSLTScriptEngine(new XSLTScriptEngine())
    ;

    private final Payload payload;

    PayloadType(Payload payload) {
        this.payload = payload;
    }

    public static PayloadType getPayloadType(String payloadType) {
        for (PayloadType value : values()) {
            if (value.name().equals(payloadType)) {
                return value;
            }
        }
        throw new IllegalArgumentException("unknown payload type: " + payloadType);
    }
}
