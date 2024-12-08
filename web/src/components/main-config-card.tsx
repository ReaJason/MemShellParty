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
import { Switch } from "@/components/ui/switch.tsx";
import { ServerIcon } from "lucide-react";

export function MainConfigCard() {
  return (
    <Card className="w-full">
      <CardHeader className="pb-1">
        <CardTitle className="text-md flex items-center gap-2">
          <ServerIcon className="h-5" />
          <span>核心配置</span>
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-2">
        <div className="grid grid-cols-2 gap-2">
          <div className="space-y-1">
            <Label htmlFor="server" className="text-sm">
              目标服务
            </Label>
            <Select>
              <SelectTrigger id="server" className="h-8">
                <SelectValue placeholder="请选择" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="tomcat">Tomcat</SelectItem>
                <SelectItem value="jetty">Jetty</SelectItem>
                <SelectItem value="undertow">Undertow</SelectItem>
                <SelectItem value="jboss">JBoss</SelectItem>
                <SelectItem value="wildfly">Wildfly</SelectItem>
                <SelectItem value="springmvc">SpringMVC</SelectItem>
                <SelectItem value="springwebflux">SpringWebflux</SelectItem>
                <SelectItem value="weblogic">WebLogic</SelectItem>
                <SelectItem value="websphere">WebSphere</SelectItem>
                <SelectItem value="resin">Resin</SelectItem>
                <SelectItem value="glassfish">Glassfish</SelectItem>
                <SelectItem value="bes">BES</SelectItem>
                <SelectItem value="tongweb">TongWeb</SelectItem>
              </SelectContent>
            </Select>
          </div>
          <div className="space-y-1">
            <Label htmlFor="targetJdkVersion" className="text-sm">
              JRE
            </Label>
            <Select defaultValue="6">
              <SelectTrigger id="targetJdkVersion" className="h-8">
                <SelectValue placeholder="请选择" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="6">Java 6</SelectItem>
                <SelectItem value="7">Java 7</SelectItem>
                <SelectItem value="8">Java 8</SelectItem>
                <SelectItem value="9">Java 9</SelectItem>
                <SelectItem value="11">Java 11</SelectItem>
                <SelectItem value="17">Java 17</SelectItem>
              </SelectContent>
            </Select>
          </div>
        </div>
        <div className="grid grid-cols-2 gap-2">
          <div>
            <Label htmlFor="shellClassName" className="text-sm">
              自定义内存马类名（可选）
            </Label>
            <Input id="shellClassName" placeholder="请输入" className="h-8" />
          </div>
          <div>
            <Label htmlFor="injectorClassName" className="text-sm">
              自定义注入器类名（可选）
            </Label>
            <Input id="injectorClassName" placeholder="请输入" className="h-8" />
          </div>
        </div>
        <div className="flex items-center space-x-4">
          <div className="flex items-center space-x-2">
            <Switch id="obfuscate" />
            <Label htmlFor="obfuscate" className="text-sm">
              开启混淆
            </Label>
          </div>
          <div className="flex items-center space-x-2">
            <Switch id="debug" />
            <Label htmlFor="debug" className="text-sm">
              开启调试
            </Label>
          </div>
          <div className="flex items-center space-x-2">
            <Switch id="lambda" />
            <Label htmlFor="debug" className="text-sm">
              Lambda 类名
            </Label>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}
