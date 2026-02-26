package com.reajason.javaweb.packer;

import com.reajason.javaweb.packer.spec.PackerSchema;

import java.lang.reflect.ParameterizedType;
import java.lang.reflect.Type;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * @author ReaJason
 * @since 2024/11/26
 */
public interface Packer<T> {
    TypeCache TYPE_CACHE = new TypeCache();

    /**
     * 将自定义类打包成特定 payload
     *
     * @param classPackerConfig 自定义类信息
     * @return 字符串 payload
     */
    default String pack(ClassPackerConfig<T> classPackerConfig) {
        throw new UnsupportedOperationException("当前 " + this.getClass().getSimpleName() + " 不支持 string 生成");
    }

    @SuppressWarnings("unchecked")
    default Class<T> customConfigType() {
        Optional<Class<?>> resolved = TYPE_CACHE.cache.computeIfAbsent(this.getClass(), TypeResolver::resolveCustomConfigType);
        return (Class<T>) resolved.orElse(null);
    }

    default T resolveCustomConfig(Object rawCustomConfig) {
        Class<T> clazz = customConfigType();
        if (clazz == null) {
            return null;
        }
        return PackerConfigConverter.convert(rawCustomConfig, clazz);
    }

    /**
     * Packer config schema for UI rendering.
     */
    default PackerSchema schema() {
        return PackerSchema.empty();
    }

    final class TypeCache {
        private final Map<Class<?>, Optional<Class<?>>> cache = new ConcurrentHashMap<>();
    }

    final class TypeResolver {
        private TypeResolver() {
        }

        private static Optional<Class<?>> resolveCustomConfigType(Class<?> clazz) {
            Class<?> current = clazz;
            while (current != null && current != Object.class) {
                Optional<Class<?>> fromInterfaces = resolveFromTypes(current.getGenericInterfaces());
                if (fromInterfaces.isPresent()) {
                    return fromInterfaces;
                }
                current = current.getSuperclass();
            }
            return Optional.empty();
        }

        private static Optional<Class<?>> resolveFromTypes(Type[] types) {
            for (Type type : types) {
                if (!(type instanceof ParameterizedType)) {
                    continue;
                }
                ParameterizedType parameterizedType = (ParameterizedType) type;
                if (!(parameterizedType.getRawType() instanceof Class)) {
                    continue;
                }
                Class<?> rawType = (Class<?>) parameterizedType.getRawType();
                if (rawType != Packer.class) {
                    continue;
                }
                Type configType = parameterizedType.getActualTypeArguments()[0];
                if (configType instanceof Class) {
                    return Optional.of((Class<?>) configType);
                }
                return Optional.empty();
            }
            return Optional.empty();
        }
    }
}
