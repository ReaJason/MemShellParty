/**
 * @author ReaJason
 * @since 2025/6/27
 */
public class CommandExec {
    static {
        try {
            java.nio.file.Files.write(
                    java.nio.file.Paths.get(System.getProperty("java.io.tmpdir"),
                            System.getProperty("memshell.vul.rce.marker", "memshell-vul-rce-proof.txt")),
                    "rce".getBytes());
        } catch (Exception e) {

        }
    }
}
