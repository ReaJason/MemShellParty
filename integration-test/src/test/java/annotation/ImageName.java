package annotation;

import java.lang.annotation.Documented;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;

/**
 * @author ReaJason
 * @since 2024/11/28
 */
@Documented
@Retention(RetentionPolicy.RUNTIME)
public @interface ImageName {

    String value();
}
