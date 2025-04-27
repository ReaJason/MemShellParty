package com.reajason.javaweb.memshell.config;

import com.reajason.javaweb.memshell.utils.CommonUtil;
import lombok.Builder;
import lombok.Getter;
import lombok.ToString;
import lombok.experimental.SuperBuilder;

/**
 * @author ReaJason
 * @since 2024/11/24
 */
@Getter
@SuperBuilder
@ToString
public class CommandConfig extends ShellToolConfig {
    @Builder.Default
    private String paramName = CommonUtil.getRandomString(8);

    @Builder.Default
    private Encryptor encryptor = Encryptor.RAW;

    public enum Encryptor {
        RAW, DOUBLE_BASE64;

        public static Encryptor fromString(String encryptor) {
            if (encryptor != null && encryptor.equals("DOUBLE_BASE64")) {
                return DOUBLE_BASE64;
            }
            return RAW;
        }
    }
}
