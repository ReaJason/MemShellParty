package com.reajason.javaweb.packer.base64;

import com.reajason.javaweb.packer.spec.PackerFieldSchema;
import com.reajason.javaweb.packer.spec.PackerFieldType;
import com.reajason.javaweb.packer.spec.PackerSchema;
import lombok.Data;

@Data
public class Base64CustomPackerConfig {
    private boolean urlEncoded;
    private boolean gzipCompressed;

    public static PackerSchema schema() {
        PackerFieldSchema urlEncodedField = new PackerFieldSchema();
        urlEncodedField.setKey("urlEncoded");
        urlEncodedField.setType(PackerFieldType.BOOLEAN);
        urlEncodedField.setRequired(false);
        urlEncodedField.setDefaultValue(false);
        urlEncodedField.setDescription("Enable URL encoding");
        urlEncodedField.setDescriptionI18nKey("urlEncoded.desc");

        PackerFieldSchema gzipCompressedField = new PackerFieldSchema();
        gzipCompressedField.setKey("gzipCompressed");
        gzipCompressedField.setType(PackerFieldType.BOOLEAN);
        gzipCompressedField.setRequired(false);
        gzipCompressedField.setDefaultValue(false);
        gzipCompressedField.setDescription("Enable GZIP compression");
        gzipCompressedField.setDescriptionI18nKey("gzipCompressed.desc");

        PackerSchema schema = new PackerSchema();
        schema.getFields().add(urlEncodedField);
        schema.getFields().add(gzipCompressedField);
        schema.getDefaultConfig().put("urlEncoded", false);
        schema.getDefaultConfig().put("gzipCompressed", false);
        return schema;
    }
}
