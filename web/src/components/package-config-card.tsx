import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card.tsx";
import { Label } from "@/components/ui/label.tsx";
import { RadioGroup, RadioGroupItem } from "@/components/ui/radio-group.tsx";
import { PackageIcon } from "lucide-react";

export function PackageConfigCard() {
  return (
    <Card className="w-full">
      <CardHeader className="pb-1">
        <CardTitle className="text-md flex items-center gap-2">
          <PackageIcon className="h-5" />
          <span>打包配置</span>
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-2">
        <div className="space-y-1">
          <Label className="text-sm">打包方式</Label>
          <RadioGroup defaultValue="base64">
            <div className="grid grid-cols-2 gap-2">
              <div className="flex items-center space-x-2">
                <RadioGroupItem value="base64" id="base64" />
                <Label htmlFor="base64" className="text-xs">
                  Base64
                </Label>
              </div>
              <div className="flex items-center space-x-2">
                <RadioGroupItem value="jsp" id="jsp" />
                <Label htmlFor="jsp" className="text-xs">
                  JSP
                </Label>
              </div>
              <div className="flex items-center space-x-2">
                <RadioGroupItem value="classFile" id="classFile" />
                <Label htmlFor="classFile" className="text-xs">
                  反序列化
                </Label>
              </div>
              <div className="flex items-center space-x-2">
                <RadioGroupItem value="scriptEngine" id="scriptEngine" />
                <Label htmlFor="scriptEngine" className="text-xs">
                  ScriptEngine
                </Label>
              </div>
              <div className="flex items-center space-x-2">
                <RadioGroupItem value="elExpression" id="elExpression" />
                <Label htmlFor="elExpression" className="text-xs">
                  EL Expression
                </Label>
              </div>
              <div className="flex items-center space-x-2">
                <RadioGroupItem value="ognlExpression" id="ognlExpression" />
                <Label htmlFor="ognlExpression" className="text-xs">
                  OGNL Expression
                </Label>
              </div>
              <div className="flex items-center space-x-2">
                <RadioGroupItem value="spelExpression" id="spelExpression" />
                <Label htmlFor="spelExpression" className="text-xs">
                  SpEL Expression
                </Label>
              </div>
              <div className="flex items-center space-x-2">
                <RadioGroupItem value="elExpression" id="elExpression" />
                <Label htmlFor="elExpression" className="text-xs">
                  EL Expression
                </Label>
              </div>
              <div className="flex items-center space-x-2">
                <RadioGroupItem value="freemarkerExpression" id="freemarkerExpression" />
                <Label htmlFor="freemarkerExpression" className="text-xs">
                  Freemarker
                </Label>
              </div>
              <div className="flex items-center space-x-2">
                <RadioGroupItem value="velocityExpression" id="velocityExpression" />
                <Label htmlFor="velocityExpression" className="text-xs">
                  Velocity
                </Label>
              </div>
            </div>
          </RadioGroup>
        </div>
      </CardContent>
    </Card>
  );
}
