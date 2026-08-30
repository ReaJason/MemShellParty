const isNode =
    typeof process !== "undefined" &&
    process?.versions?.node != null;
const wasmPath = async () => {
    const url = new URL("./cfr.wasm", import.meta.url).href;
    return isNode ? await import("node:url").then((mod) => mod.fileURLToPath(url)) : url;
};

let decompileFunc = null;
export const decompile = async (name, options) => {
    if (!decompileFunc) {
        const { load } = await import("./cfr.wasm-runtime.js");
        const { exports } = await load(await wasmPath(), { noAutoImports: true });

        decompileFunc = exports.decompile;
    }

    return decompileFunc(name, options);
};
