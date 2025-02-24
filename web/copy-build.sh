#!/bin/bash

echo "Copy asserts into SpringBoot resources"
# 定义目标路径
BASE_DIR="../boot/src/main/resources"
STATIC_DIR="$BASE_DIR/static"
ASSETS_DIR="$STATIC_DIR/assets"
TEMPLATES_DIR="$BASE_DIR/templates"
SRC_DIR="dist"

# 检查 dist 目录是否存在
if [ ! -d "$SRC_DIR" ]; then
    echo "fail: $SRC_DIR not exists"
    exit 1
fi

# 确定使用 sed 还是 gsed
if [[ "$OSTYPE" == "darwin"* ]]; then
    SED_CMD="gsed"
    if ! command -v gsed &> /dev/null; then
        echo "fail: macOS need install gsed (by 'brew install gnu-sed')"
        exit 1
    fi
else
    SED_CMD="sed"
fi

# 创建目录（如果不存在）
mkdir -p "$ASSETS_DIR" "$TEMPLATES_DIR"

# 检查并清理 assets 目录
rm -rf "$ASSETS_DIR"/*

# 复制静态文件
cp "$SRC_DIR/vite.svg" "$STATIC_DIR/"
cp -R "$SRC_DIR/assets/"* "$ASSETS_DIR/"

# 处理 index.html
INDEX_SRC="$SRC_DIR/index.html"
INDEX_DEST="$TEMPLATES_DIR/index.html"

if [ ! -f "$INDEX_SRC" ]; then
    echo "fail: $INDEX_SRC not exists, make sure you had built frontend project with bun run build"
    exit 1
fi

# 创建临时文件进行 thymeleaf 语法转换
TEMP_FILE=$(mktemp)
cp "$INDEX_SRC" "$TEMP_FILE"

"$SED_CMD" -i 's/href="\([^"]*\)"/th:href="@{\1}"/g' "$TEMP_FILE"
"$SED_CMD" -i 's/src="\([^"]*\)"/th:src="@{\1}"/g' "$TEMP_FILE"

cp "$TEMP_FILE" "$INDEX_DEST"
rm "$TEMP_FILE"
echo "SpringBoot resources update successfully"