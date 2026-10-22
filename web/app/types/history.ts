import type { MemShellResult } from "@/types/memshell";
import type { ProbeShellResult } from "@/types/probeshell";
import type { MemShellFormSchema, ProbeShellFormSchema } from "@/types/schema";

interface GenerationRecordBase {
  id: string;
  createdAt: number;
  used: boolean;
  packMethod: string;
  packResult?: string;
}

export interface MemShellGenerationRecord extends GenerationRecordBase {
  kind: "memshell";
  formValues: MemShellFormSchema;
  result: MemShellResult;
}

export interface ProbeGenerationRecord extends GenerationRecordBase {
  kind: "probe";
  formValues: ProbeShellFormSchema;
  result: ProbeShellResult;
}

export type GenerationRecord = MemShellGenerationRecord | ProbeGenerationRecord;
