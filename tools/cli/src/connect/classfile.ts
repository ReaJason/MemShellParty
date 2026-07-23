/**
 * Minimal Java class-file rewriter.
 *
 * Behinder sends "payload template" classes whose static String fields are
 * filled client-side before upload (its `Params.getParamedClass` uses ASM to
 * set a `ConstantValue` on the field). We only need that one feature: set a
 * static String field's ConstantValue, leaving everything else byte-identical.
 */

const CONSTANT_VALUE = "ConstantValue";

class Cursor {
  constructor(readonly buf: Buffer) {}
  u1(off: number): number {
    return this.buf.readUInt8(off);
  }
  u2(off: number): number {
    return this.buf.readUInt16BE(off);
  }
}

interface PoolInfo {
  count: number;
  /** offset just past the last pool entry */
  end: number;
  utf8: Map<number, string>;
  constantValueNameIndex: number; // 0 = absent
}

function readPool(cur: Cursor): PoolInfo {
  const buf = cur.buf;
  const count = cur.u2(8);
  const utf8 = new Map<number, string>();
  let constantValueNameIndex = 0;
  let off = 10;
  for (let i = 1; i < count; i++) {
    const tag = cur.u1(off);
    switch (tag) {
      case 1: {
        const len = cur.u2(off + 1);
        const value = decodeModifiedUtf8(buf, off + 3, off + 3 + len);
        utf8.set(i, value);
        if (value === CONSTANT_VALUE) constantValueNameIndex = i;
        off += 3 + len;
        break;
      }
      case 3: // Integer
      case 4: // Float
      case 9: // Fieldref
      case 10: // Methodref
      case 11: // InterfaceMethodref
      case 12: // NameAndType
      case 17: // Dynamic
      case 18: // InvokeDynamic
        off += 5;
        break;
      case 5: // Long — two slots
      case 6: // Double — two slots
        off += 9;
        i++;
        break;
      case 7: // Class
      case 8: // String
      case 16: // MethodType
      case 19: // Module
      case 20: // Package
        off += 3;
        break;
      case 15: // MethodHandle
        off += 4;
        break;
      default:
        throw new Error(`unsupported constant pool tag ${tag} at index ${i}`);
    }
  }
  return { count, end: off, utf8, constantValueNameIndex };
}

/**
 * Decode a CONSTANT_Utf8 payload (modified UTF-8): 1/2/3-byte forms,
 * surrogate code units reassemble into supplementary characters, C0 80 is
 * U+0000. Anything else decodes to U+FFFD without aborting the walk.
 */
function decodeModifiedUtf8(buf: Buffer, start: number, end: number): string {
  let out = "";
  let i = start;
  while (i < end) {
    const b = buf[i]!;
    if (b < 0x80) {
      out += String.fromCharCode(b);
      i += 1;
    } else if ((b & 0xe0) === 0xc0 && i + 1 < end) {
      out += String.fromCharCode(((b & 0x1f) << 6) | (buf[i + 1]! & 0x3f));
      i += 2;
    } else if ((b & 0xf0) === 0xe0 && i + 2 < end) {
      out += String.fromCharCode(
        ((b & 0x0f) << 12) | ((buf[i + 1]! & 0x3f) << 6) | (buf[i + 2]! & 0x3f),
      );
      i += 3;
    } else {
      out += "�";
      i += 1;
    }
  }
  return out;
}

function encodeUtf8Entry(value: string): Buffer {
  const data = encodeModifiedUtf8(value);
  const out = Buffer.alloc(3);
  out.writeUInt8(1, 0);
  out.writeUInt16BE(data.length, 1);
  return Buffer.concat([out, data]);
}

/**
 * The class-file CONSTANT_Utf8 format is *modified* UTF-8, not plain UTF-8:
 * U+0000 is written as C0 80, and characters above the BMP are written as
 * UTF-16 surrogate pairs of 3-byte sequences (plain 4-byte UTF-8 is invalid
 * and makes the JVM reject the class). Iterating UTF-16 code units gives us
 * exactly that encoding.
 */
function encodeModifiedUtf8(value: string): Buffer {
  const bytes: number[] = [];
  for (let i = 0; i < value.length; i++) {
    const code = value.charCodeAt(i);
    if (code >= 0x01 && code <= 0x7f) {
      bytes.push(code);
    } else if (code <= 0x07ff) {
      bytes.push(0xc0 | (code >> 6), 0x80 | (code & 0x3f));
    } else {
      bytes.push(0xe0 | (code >> 12), 0x80 | ((code >> 6) & 0x3f), 0x80 | (code & 0x3f));
    }
  }
  return Buffer.from(bytes);
}

/**
 * Return a copy of `classBytes` where the static String field `fieldName`
 * carries `ConstantValue = value` (added or replaced).
 */
export function injectStringConstant(
  classBytes: Buffer,
  fieldName: string,
  value: string,
): Buffer {
  const cur = new Cursor(classBytes);
  if (cur.buf.readUInt32BE(0) !== 0xcafebabe) {
    throw new Error("not a Java class file");
  }
  const pool = readPool(cur);

  // walk to the fields section
  let off = pool.end;
  off += 6; // access_flags, this_class, super_class
  const interfacesCount = cur.u2(off);
  off += 2 + interfacesCount * 2;
  const fieldsCount = cur.u2(off);
  off += 2;

  // new constant pool entries (appended at the end, so all existing
  // references keep working)
  const newEntries: Buffer[] = [];
  let nextIndex = pool.count;

  let cvNameIndex = pool.constantValueNameIndex;
  if (cvNameIndex === 0) {
    newEntries.push(encodeUtf8Entry(CONSTANT_VALUE));
    cvNameIndex = nextIndex++;
  }
  newEntries.push(encodeUtf8Entry(value));
  const valueUtf8Index = nextIndex++;
  const stringEntry = Buffer.alloc(3);
  stringEntry.writeUInt8(8, 0); // String tag
  stringEntry.writeUInt16BE(valueUtf8Index, 1);
  newEntries.push(stringEntry);
  const valueStringIndex = nextIndex++;

  for (let f = 0; f < fieldsCount; f++) {
    const fieldStart = off;
    const nameIndex = cur.u2(off + 2);
    const descIndex = cur.u2(off + 4);
    const attrCountOff = off + 6;
    const attrCount = cur.u2(attrCountOff);
    off += 8;
    const name = pool.utf8.get(nameIndex);
    const desc = pool.utf8.get(descIndex);
    const isTarget = name === fieldName && desc === "Ljava/lang/String;";

    for (let a = 0; a < attrCount; a++) {
      const attrNameIndex = cur.u2(off);
      const attrLen = cur.buf.readUInt32BE(off + 2);
      if (
        isTarget &&
        pool.constantValueNameIndex !== 0 &&
        attrNameIndex === pool.constantValueNameIndex
      ) {
        // replace existing ConstantValue in place: [fieldStart..off+6) + new idx + rest
        const patched = Buffer.from(classBytes.subarray(off, off + 6 + attrLen));
        patched.writeUInt16BE(valueStringIndex, 6);
        return Buffer.concat([
          headWithNewPool(classBytes, pool, newEntries),
          classBytes.subarray(pool.end, off),
          patched,
          classBytes.subarray(off + 6 + attrLen),
        ]);
      }
      off += 6 + attrLen;
    }

    if (isTarget) {
      // append a new ConstantValue attribute to this field
      const newAttr = Buffer.alloc(8);
      newAttr.writeUInt16BE(cvNameIndex, 0);
      newAttr.writeUInt32BE(2, 2);
      newAttr.writeUInt16BE(valueStringIndex, 6);
      const fieldBytes = Buffer.from(classBytes.subarray(fieldStart, off));
      fieldBytes.writeUInt16BE(attrCount + 1, 6);
      return Buffer.concat([
        headWithNewPool(classBytes, pool, newEntries),
        classBytes.subarray(pool.end, fieldStart),
        fieldBytes,
        newAttr,
        classBytes.subarray(off),
      ]);
    }
  }
  throw new Error(`field ${fieldName} (Ljava/lang/String;) not found in class`);
}

/**
 * Read back a static String field's ConstantValue, or null when absent.
 * Mirrors the injection above; useful for verification and test harnesses.
 */
export function readStringConstant(classBytes: Buffer, fieldName: string): string | null {
  const cur = new Cursor(classBytes);
  if (cur.buf.readUInt32BE(0) !== 0xcafebabe) {
    throw new Error("not a Java class file");
  }
  const pool = readPool(cur);
  const strings = new Map<number, number>();
  {
    let off = 10;
    for (let i = 1; i < pool.count; i++) {
      const tag = cur.u1(off);
      if (tag === 8) strings.set(i, cur.u2(off + 1));
      if (tag === 1) off += 3 + cur.u2(off + 1);
      else if ([3, 4, 9, 10, 11, 12, 17, 18].includes(tag)) off += 5;
      else if (tag === 5 || tag === 6) {
        off += 9;
        i++;
      } else if ([7, 8, 16, 19, 20].includes(tag)) off += 3;
      else if (tag === 15) off += 4;
      else throw new Error(`unsupported constant pool tag ${tag} at index ${i}`);
    }
  }

  let off = pool.end + 6;
  const interfacesCount = cur.u2(off);
  off += 2 + interfacesCount * 2;
  const fieldsCount = cur.u2(off);
  off += 2;
  for (let f = 0; f < fieldsCount; f++) {
    const name = pool.utf8.get(cur.u2(off + 2));
    const attrCount = cur.u2(off + 6);
    off += 8;
    for (let a = 0; a < attrCount; a++) {
      const attrNameIndex = cur.u2(off);
      const attrLen = cur.buf.readUInt32BE(off + 2);
      if (
        name === fieldName &&
        pool.constantValueNameIndex !== 0 &&
        attrNameIndex === pool.constantValueNameIndex
      ) {
        const utf8Index = strings.get(cur.u2(off + 6));
        return utf8Index === undefined ? null : (pool.utf8.get(utf8Index) ?? null);
      }
      off += 6 + attrLen;
    }
  }
  return null;
}

/** file head (through the pool) with patched pool count + appended entries */
function headWithNewPool(classBytes: Buffer, pool: PoolInfo, newEntries: Buffer[]): Buffer {
  const head = Buffer.from(classBytes.subarray(0, pool.end));
  head.writeUInt16BE(pool.count + newEntries.length, 8);
  return Buffer.concat([head, ...newEntries]);
}
