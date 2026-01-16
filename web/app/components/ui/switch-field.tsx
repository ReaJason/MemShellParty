import { InfoIcon } from "lucide-react";
import { memo } from "react";
import {
  type Control,
  Controller,
  type FieldValues,
  type Path,
} from "react-hook-form";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/ui/tooltip";

// Hoisted static JSX to avoid recreation on each render
const infoIcon = (
  <InfoIcon className="h-3.5 w-3.5 text-muted-foreground cursor-help" />
);

interface SwitchFieldProps<T extends FieldValues> {
  readonly name: Path<T>;
  readonly label: string;
  readonly description: string;
  readonly control: Control<T>;
}

function SwitchFieldInner<T extends FieldValues>({
  name,
  label,
  description,
  control,
}: SwitchFieldProps<T>) {
  return (
    <Controller
      control={control}
      name={name}
      render={({ field }) => (
        <div className="flex items-center gap-2">
          <Switch
            id={name}
            checked={field.value}
            onCheckedChange={field.onChange}
          />
          <Label htmlFor={name}>{label}</Label>
          <Tooltip>
            <TooltipTrigger>{infoIcon}</TooltipTrigger>
            <TooltipContent>
              <p>{description}</p>
            </TooltipContent>
          </Tooltip>
        </div>
      )}
    />
  );
}

export const SwitchField = memo(SwitchFieldInner) as typeof SwitchFieldInner;
