import java.io.IOException;

/**
 * @author ReaJason
 * @since 2025/6/27
 */
public class CommandExec {
    static {
        try {
            java.lang.Runtime.getRuntime().exec("open -a Calculator");
        } catch (IOException e) {

        }
    }
}
