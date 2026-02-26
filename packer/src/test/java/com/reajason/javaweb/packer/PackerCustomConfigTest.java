package com.reajason.javaweb.packer;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.Map;

class PackerCustomConfigTest {

    @Test
    void typedPackerShouldInferCustomConfigType() {
        TypedDemoPacker packer = new TypedDemoPacker();
        Assertions.assertEquals(DemoCustomConfig.class, packer.customConfigType());
    }

    @Test
    void rawPackerShouldTreatAsNoCustomConfig() {
        RawDemoPacker packer = new RawDemoPacker();
        Assertions.assertNull(packer.customConfigType());
        Assertions.assertNull(packer.resolveCustomConfig(Map.of("enabled", true)));
    }

    @Test
    void typedPackerShouldResolveCustomConfig() {
        TypedDemoPacker packer = new TypedDemoPacker();
        DemoCustomConfig resolved = packer.resolveCustomConfig(Map.of(
                "name", "demo",
                "enabled", true,
                "count", 7
        ));
        Assertions.assertEquals("demo", resolved.getName());
        Assertions.assertTrue(resolved.isEnabled());
        Assertions.assertEquals(7, resolved.getCount());
    }

    @Test
    void typedPackerShouldReturnDefaultWhenNull() {
        TypedDemoPackerWithDefault packer = new TypedDemoPackerWithDefault();
        DemoCustomConfig resolved = packer.resolveCustomConfig(null);
        Assertions.assertNotNull(resolved);
        Assertions.assertEquals("default", resolved.getName());
        Assertions.assertEquals(9, resolved.getCount());
    }

    static class TypedDemoPacker implements Packer<DemoCustomConfig> {
    }

    static class TypedDemoPackerWithDefault implements Packer<DemoCustomConfig> {
        @Override
        public DemoCustomConfig defaultCustomConfig() {
            DemoCustomConfig config = new DemoCustomConfig();
            config.setName("default");
            config.setCount(9);
            return config;
        }
    }

    static class RawDemoPacker implements Packer {
    }

    public static class DemoCustomConfig {
        private String name;
        private boolean enabled;
        private int count;

        public String getName() {
            return name;
        }

        public void setName(String name) {
            this.name = name;
        }

        public boolean isEnabled() {
            return enabled;
        }

        public void setEnabled(boolean enabled) {
            this.enabled = enabled;
        }

        public int getCount() {
            return count;
        }

        public void setCount(int count) {
            this.count = count;
        }
    }
}
