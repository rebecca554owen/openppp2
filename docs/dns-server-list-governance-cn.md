# PPP_PUBLIC_DNS_SERVER_LIST 维护治理规范

> 本文档描述 `ppp/stdafx.h` 中 `PPP_PUBLIC_DNS_SERVER_LIST` 数组的维护规则，
> 防止因隐式字符串拼接导致的回归问题（参见 deep-code-audit P2-3）。

## 1. 问题背景

C/C++ 中相邻的字符串字面量会被编译器隐式拼接：

```cpp
"120.53.53.53"       // ← 如果此处漏掉逗号
"8.8.8.8"            // ← 编译器会将其拼接为 "120.53.53.538.8.8.8"
```

这会导致：
- 产生非法 IP 地址
- 数组元素总数减少一个
- 运行时 DNS 解析静默失败

历史上 `PPP_PREFERRED_DNS_SERVER_1`（宏展开为 `"8.8.8.8"`）前曾漏掉逗号，
导致上述隐式拼接。

## 2. 当前防护措施

### 2.1 边界注释

```cpp
// ---- PPP_PUBLIC_DNS_SERVER_LIST begins ----
// Each entry MUST be a separate comma-separated string literal.
// PPP_PREFERRED_DNS_SERVER_1/2 are #define macros (expand to string literals);
// a missing comma before them would cause C/C++ implicit adjacent-string concatenation.
static constexpr const char* PPP_PUBLIC_DNS_SERVER_LIST[] = {
    ...
};
// P2-3 regression guard: pin the expected entry count ...
static_assert(sizeof(PPP_PUBLIC_DNS_SERVER_LIST) / sizeof(PPP_PUBLIC_DNS_SERVER_LIST[0]) == 56,
              "PPP_PUBLIC_DNS_SERVER_LIST entry count changed - did you forget a comma?");
// ---- PPP_PUBLIC_DNS_SERVER_LIST ends ----
```

### 2.2 编译期 `static_assert`

在数组声明之后紧跟一个 `static_assert`，固定元素计数为 **56**。

**效果：**
- 如果任何两个条目因漏逗号而合并，元素数变为 55，编译失败。
- 如果新增条目但忘记更新断言数字，同样编译失败——强制开发者人工核对条目数。

**局限：**
- 不能检测单个条目的 IP 格式是否合法。
- 不能检测是否多了/少了合法条目（只校验总数）。

## 3. 修改规则

### 3.1 新增 DNS 条目

1. 在数组中合适位置添加新条目，确保前后均有逗号。
2. 更新 `static_assert` 中的数字（当前为 56，新增 1 条则改为 57）。
3. 本地编译验证 `static_assert` 通过。

### 3.2 删除 DNS 条目

1. 删除目标条目，确保不留悬空逗号。
2. 更新 `static_assert` 中的数字。
3. 本地编译验证。

### 3.3 修改宏展开项

`PPP_PREFERRED_DNS_SERVER_1` 和 `PPP_PREFERRED_DNS_SERVER_2` 是 `#define` 宏，
展开后为字符串字面量。修改宏定义本身不影响条目数，但修改其在数组中的位置时
需格外注意逗号。

## 4. 后续可测试策略（未实现）

以下策略目前 **尚未实现**，仅作为后续参考：

### 4.1 编译期 IPv4 格式校验（C++17 constexpr）

理论上可以用 `constexpr` 函数逐字符校验每个字符串是否符合 `d.d.d.d` 格式，
但当前数组包含宏展开项（`PPP_PREFERRED_DNS_SERVER_1/2`），`constexpr` 上下文中
当前未实现逐项 `constexpr` IPv4 格式校验，现阶段仅保留条目计数防护。
若后续要做逐项校验，可先把宏展开项收敛为统一的 `constexpr` 字符串变量或使用测试脚本生成校验报告，避免在超级头文件中引入复杂模板解析逻辑。

### 4.2 单元测试 / 外部脚本

在 CI 中增加一个简单脚本（Python/shell），从 `ppp/stdafx.h` 中提取数组内容，
用正则逐项校验 IP 格式。优点是不依赖 C++ 编译期能力，缺点是需要额外的 CI 步骤。

### 4.3 代码审查清单

在 PR 模板中增加一项检查：「如果修改了 `PPP_PUBLIC_DNS_SERVER_LIST`，
是否同步更新了 `static_assert` 中的条目计数？」
