import type {
  LegacyPackerGroup,
  PackerCategory,
  PackerConfig,
  PackerEntry,
  PackerSchemaField,
} from "@/types/memshell";

export type NormalizedPackerEntry = Pick<
  PackerEntry,
  "name" | "outputKind" | "categoryAnchor" | "schema"
>;

export type NormalizedPackerCategory = {
  name: string;
  packers: NormalizedPackerEntry[];
};

const isLegacyGroup = (value: unknown): value is LegacyPackerGroup => {
  return (
    typeof value === "object" &&
    value !== null &&
    "group" in value &&
    "options" in value &&
    Array.isArray((value as { options?: unknown[] }).options)
  );
};

const isPackerCategory = (value: unknown): value is PackerCategory => {
  return (
    typeof value === "object" &&
    value !== null &&
    "name" in value &&
    "packers" in value &&
    Array.isArray((value as { packers?: unknown[] }).packers)
  );
};

export function normalizePackerCategories(
  packerConfig: PackerConfig | undefined,
): NormalizedPackerCategory[] {
  return (packerConfig ?? [])
    .map((item): NormalizedPackerCategory | null => {
      if (typeof item === "string") {
        return {
          name: item,
          packers: [{ name: item, categoryAnchor: false }],
        };
      }
      if (isLegacyGroup(item)) {
        return {
          name: item.group,
          packers: (item.options ?? []).map((name) => ({
            name,
            categoryAnchor: false,
          })),
        };
      }
      if (isPackerCategory(item)) {
        return {
          name: item.name,
          packers: (item.packers ?? []).map((packer) => ({
            name: packer.name,
            outputKind: packer.outputKind,
            categoryAnchor: !!packer.categoryAnchor,
            schema: packer.schema,
          })),
        };
      }
      return null;
    })
    .filter((item): item is NormalizedPackerCategory => item !== null);
}

export function findPackerEntry(
  categories: NormalizedPackerCategory[],
  packerName: string | undefined,
): NormalizedPackerEntry | undefined {
  if (!packerName) {
    return undefined;
  }
  for (const category of categories) {
    const found = category.packers.find((packer) => packer.name === packerName);
    if (found) {
      return found;
    }
  }
  return undefined;
}

export function getPackerSchemaFields(
  packer: NormalizedPackerEntry | undefined,
): PackerSchemaField[] {
  return packer?.schema?.fields ?? [];
}

export function getPackerDefaultConfig(
  packer: NormalizedPackerEntry | undefined,
): Record<string, unknown> {
  return { ...(packer?.schema?.defaultConfig ?? {}) };
}
