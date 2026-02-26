package com.reajason.javaweb.packer.jsp;

import com.reajason.javaweb.packer.spec.PackerFieldSchema;
import com.reajason.javaweb.packer.spec.PackerFieldType;
import com.reajason.javaweb.packer.spec.PackerSchema;
import lombok.Data;

/**
 * @author ReaJason
 * @since 2026/2/26
 */
@Data
public class JspCustomPackerConfig {
    private boolean unicode;

    public static PackerSchema schema() {
        PackerFieldSchema unicodeField = new PackerFieldSchema();
        unicodeField.setKey("unicode");
        unicodeField.setType(PackerFieldType.BOOLEAN);
        unicodeField.setRequired(false);
        unicodeField.setDefaultValue(false);
        unicodeField.setDescription("Enable Unicode encoding");
        unicodeField.setDescriptionI18nKey("unicodeEncoded.desc");

        PackerSchema schema = new PackerSchema();
        schema.getFields().add(unicodeField);
        schema.getDefaultConfig().put("unicode", false);
        return schema;
    }
}
