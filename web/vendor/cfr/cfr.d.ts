declare module "@run-slicer/cfr" {
    export type Options = Record<string, string>;

    export interface Config {
        source?: (name: string) => Uint8Array | null;
        options?: Options;
    }

    export function decompile(name: string, config?: Config): Promise<string>;
}
