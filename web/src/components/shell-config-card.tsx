import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card.tsx";
import { Input } from "@/components/ui/input.tsx";
import { Label } from "@/components/ui/label.tsx";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select.tsx";
import { FishSymbolIcon } from "lucide-react";
import { useState } from "react";

export function ShellConfigCard() {
  const [shellTool, setShellTool] = useState<string>("");
  return (
    <Card className="w-full">
      <CardHeader className="pb-1">
        <CardTitle className="text-md flex items-center gap-2">
          <FishSymbolIcon className="h-5" />
          <span>内存马配置</span>
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-2">
        <div className="space-y-1">
          <Label htmlFor="shellType" className="text-sm">
            挂载类型
          </Label>
          <Select>
            <SelectTrigger id="shellType" className="h-8">
              <SelectValue placeholder="请选择" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="filter">Filter</SelectItem>
              <SelectItem value="servlet">Servlet</SelectItem>
              <SelectItem value="listener">Listener</SelectItem>
              <SelectItem value="agent">Agent</SelectItem>
            </SelectContent>
          </Select>
        </div>
        <div className="space-y-1">
          <Label htmlFor="shellTool" className="text-sm">
            工具类型
          </Label>
          <Select onValueChange={(value: string) => setShellTool(value)}>
            <SelectTrigger id="shellTool" className="h-8">
              <SelectValue placeholder="请选择" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="command">命令执行</SelectItem>
              <SelectItem value="fileList">File List</SelectItem>
              <SelectItem value="gozilla">Godzilla</SelectItem>
            </SelectContent>
          </Select>
        </div>
        {shellTool === "gozilla" && (
          <div className="space-y-1">
            <Label className="text-sm">Godzilla 配置</Label>
            <div className="grid grid-cols-2 gap-2">
              <Input placeholder="Pass" className="h-8 text-sm" />
              <Input placeholder="Key" className="h-8 text-sm" />
              <Input placeholder="Header Name" className="h-8 text-sm" />
              <Input placeholder="Header Value" className="h-8 text-sm" />
            </div>
          </div>
        )}
        {shellTool === "command" && (
          <div className="space-y-1">
            <Label htmlFor="paramName" className="text-sm">
              接收命令请求参数
            </Label>
            <Input id="paramName" placeholder="请输入" className="h-8 text-sm" />
          </div>
        )}
      </CardContent>
    </Card>
  );
}
