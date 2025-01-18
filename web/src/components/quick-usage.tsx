import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card.tsx";

export function QuickUsage() {
  return (
    <Card>
      <CardHeader>
        <CardTitle>快速使用</CardTitle>
      </CardHeader>
      <CardContent>
        <ol className="list-decimal list-inside space-y-4 text-sm">
          <li>选择目标服务</li>
          <li>选择内存马功能，Godzilla、Behinder 或者其他</li>
          <li>选择内存马挂载类型，Filter、Listener 或者其他</li>
          <li>选择打包方式</li>
          <li>点击生成内存马</li>
        </ol>
      </CardContent>
    </Card>
  );
}
