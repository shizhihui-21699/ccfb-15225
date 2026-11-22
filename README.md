# vulnrange

从漏洞通告的**文本**和**代码仓库**中自动提取每个漏洞准确的受影响版本范围，找到
修复提交，并核对它确实落在通告声称的版本里。每一步都给出证据和可信度。

```
通告文本  ──解析──▶  声明（版本范围 / 修复版本 / 修复提交）
                          │
仓库历史  ──索引──▶  发布版本链（按维护分支分组）
                          │
                          ▼
                    交叉核对 ──▶  结论 + 证据 + 可信度 + 退出码
```

## 为什么这个问题难

安全团队每天要跟进大量通告，而通告对受影响版本的描述方式各不相同：

| 通告写法 | 实际含义 |
|---|---|
| `All releases before 2.4.0 are affected` | 单边上界，**不含** 2.4.0 |
| `2.4.0 and earlier` | 单边上界，**含** 2.4.0 |
| `>= 3.0.0, < 3.2.1` | 双侧区间 |
| `1.4.x` / `the 1.6 branch` | 按发布线（maintenance branch）切片 |
| `Fixed in commit 3f2a1bc` | 只有一个提交，没有版本 |
| `2.0 之前的所有版本` | 同上，中文 |
| `Fixed in 2.2.0 and 1.9.10` | 一条修复，两个分支各自发布 |

还有两个更隐蔽的陷阱：

* **回移（backport）**：同一处修复在主线和维护分支上是**不同提交号、相同补丁**。
  只比对提交号会漏掉维护分支，从而把已经修好的老版本误判为受影响。
* **通告本身写错**：漏写某条维护线、把已修复版本也列进受影响范围、声称的修复版本
  其实不包含修复提交。

`vulnrange` 把「文本说了什么」和「仓库里实际发生了什么」分别算出来，再逐条对照，
不一致的地方直接报出来，而不是替通告圆场。

## 安装与运行

只依赖 Python ≥ 3.10 标准库和 `git` 命令行。

```bash
python -m venv .venv && .venv/bin/pip install -e '.[dev]'
.venv/bin/python -m pytest            # 全部测试（会现场构建 git 仓库）
```

### 检查一条通告

```bash
vulnrange check advisories/CVE-2024-4242.txt --repo ~/src/demo
vulnrange check advisories/CVE-2024-9999.txt --repo-url https://github.com/example/demo --format markdown
vulnrange check adv.txt --repo . --format json -o report.json
```

### 批量

```bash
vulnrange batch advisories/*.txt --repo-root /srv/mirrors        # 每个包一个 checkout
vulnrange batch advisories/*.txt --repo /srv/mirrors/demo --summary
```

`--repo-root` 会在其下按包名、`owner__repo` 或 `owner/repo` 查找 checkout；也会读取
通告里的仓库 URL 并尝试匹配镜像。找不到对应仓库的通告会跳过并在 stderr 说明。

### 退出码（可直接用于流水线门禁）

| 码 | 含义 |
|---|---|
| 0 | 全部核对一致（或 `--fail-on never`） |
| 1 | 至少一条通告被判定为 `DISPUTED` / `CONTRADICTED` |
| 2 | 用法或环境错误（路径不存在、不是 git 仓库……） |

## 输出

每条结果有四层信息：**结论**、**依据**、**逐条证据**、**可信度与保留意见**。

```
CVE-2024-4242  —  CONFIRMED
confidence : 0.90  (high — text parsed cleanly and history agrees)
basis      : repository history (fix commits + patch-id backports)
declared   : [1.4, 1.4.9) | [1.6, 1.6.3] | [2.0.1, 2.0.1] | [2.0.2, 2.0.2]
resolved   : [1.4.0, 1.4.9) | [1.6.0, 1.6.4) | [2.0.1, 2.0.3)

Fix commits
  9e964e6ed3a5  [verified]  fix: reject unbalanced input (CVE-2024-4242)
      released in: 1.6.4
      line 1.4.x: first fixed release 1.4.9
      line 2.0.x: first fixed release 2.0.3
      · backport found on line 1.4.x: 1.4.9 (1c0a1ccd6c) has the same patch-id (c8d2cfc3118a)
```

独立跑一遍示例（会现场构建 3 个演示仓库）：

```bash
python examples/run_demo.py
```

`--format json` 输出稳定的结构化结果（`status` / `confidence` / `basis` /
`resolved_range` / `fix_commits[].evidence` / `lines` / `findings` / `notes`），
适合接入告警或工单系统。

## 结论状态与可信度

| 状态 | 含义 |
|---|---|
| `CONFIRMED` | 通告的范围与仓库历史逐条吻合 |
| `PARTIAL` | 有证据但有保留（例如修复只存在于分支、部分版本无法核对） |
| `DISPUTED` | 通告与仓库历史冲突（漏报或误报受影响版本、声称的修复版本不含修复） |
| `CONTRADICTED` | 通告自相矛盾（例如声称"不受影响"的版本其实没有修复） |

可信度由三部分组成，并在报告里写明理由：

1. 文本解析质量（每条声明自带置信度）；
2. 仓库证据强度（修复提交是否存在、是否进入过发布 tag、是否为搜索发现）；
3. 交叉核对结果（每条发布线是否吻合；每个 error 扣分，`FIX_NEVER_RELEASED` 也扣分）。

**没有修复提交时可信度被硬性封顶在 0.5**，并显式写明"仅依据通告文本"——宁可承认
不知道，也不假装核对过。

## 设计要点

### 版本号：一个可比较的统一表示

`src/vulnrange/versions/` 把 SemVer、Maven 限定词、CalVer、Debian 版本统一成一个
可比较的形式：

* 预发布排在正式版**之前**（`1.2.3-rc1 < 1.2.3`），补丁版排在**之后**（`1.2.3.post1 > 1.2.3`）；
* `.Final` / `.RELEASE` / `.GA` 等同正式版；缺失分量补零（`1.2 == 1.2.0`）；
* Debian 的 `~`、epoch、revision 走 dpkg 算法（`1.0~rc1 < 1.0`，`1.0-3ubuntu10 > 1.0-3ubuntu2`）；
* 不同方案之间比较也保持**全序且对称**，不会退化成字符串比较。

解析失败一律抛 `InvalidVersion`，由调用方显式处理，绝不猜。

### 区间代数

`VersionSet` 是若干区间的规范并集，保留开闭端点。`< 2.0` 与 `<= 2.0` 的差别正是
人工转录最常出的错，这里被显式建模，支持并、交、补、差。

### 通告解析：规则 + 分节上下文

`src/vulnrange/advisory/extract.py` 用一组语义明确的规则（上界 / 下界 / 区间 /
修复版本 / 修复提交 / 按发布线 / 全版本 / 不受影响），每条规则产出**带原文摘录和
字符区间**的声明。几个刻意的处理：

* 先把 CVE 号、日期、URL、issue 号、提交哈希**掩码**掉，避免被当成版本号；
* 按**段落**而非按行切分——通告常硬换行，`the 1.6 branch is / affected up to 1.6.3`
  必须当成一句话；
* 分节标题（`Affected versions:` / `Fixed in:` / `Not affected:`）提供上下文，
  但同一行里显式写出的语句优先；
* 同一句里出现多个真实区间（`before 2.4.0 … and 3.0.0 through 3.1.2`）会**都保留**；
  而"1.0.0 through 1.9.9"里的边界不会额外膨胀成开区间——抑制按**包含关系**判断，
  不按类别一刀切；
* 只有在通告完全没给受影响范围时，才从上界/修复版本**推断**一个，并明确标记
  `inferred …`、把置信度压到 0.55 以下。

### 仓库索引：按发布线分组

`src/vulnrange/analysis/universe.py` 把 tag 与分支整理成发布线（`1.4.x`、`2.0.x`）。
判定归属时优先用**分支名**，其次用**tag 祖先关系**：1.9 与 2.0 并行维护的项目里，
单看版本号数字无法区分，必须看分叉结构。

### 核对：三种证据

`src/vulnrange/analysis/verify.py`：

1. **修复提交落在哪些版本**：`git merge-base --is-ancestor` 精确回答"某提交是否是某
   release 的祖先"。
2. **回移识别**：`git patch-id --stable` 不受行号/上下文影响，同一补丁 cherry-pick
   后仍匹配——这是"不同哈希、同一修复"的可靠判据。
3. **通告 vs 历史**：逐条发布线算出 `declared_affected` 与 `actual_affected`，差值
   分别报 `OVER_DECLARED` / `UNDER_DECLARED` / `ADVISORY_CONTRADICTION`，每条都带
   tag 与提交号。

当通告完全没提修复提交时，会按 CVE 号（首选）或关键词（次选）在提交信息里搜索，
并把结果标记为 `discovered`——它只是**佐证**，可信度相应扣分。

### 保守原则

* 拿不到修复提交 → 不从历史推断受影响版本，只保留通告声明并封顶可信度；
* 版本号解析不了 → 排除并注明，不猜；
* 通告与历史冲突 → 以历史为准给出 `resolved_range`，但把冲突逐条写进 `findings`。

## 测试数据

`tools/build_fixtures.py` 现场构建 6 个具有真实历史形状的仓库：

| 场景 | 考察点 |
|---|---|
| `multi-branch` | 一次修复经 cherry-pick 落到 1.4.x / 2.0.x，哈希不同、补丁相同 |
| `fix-never-shipped` | 修复只存在于分支，从未发布 → 所有已发布版本仍受影响 |
| `wrong-advisory` | 通告漏写 1.1.x 整条线 |
| `calver` | 日历版本 + 预发布 tag |
| `missing-fix-commit` | 通告引用了本仓库不存在的提交 |
| `epoch-debian` | Debian revision 排序（`-2` < `-10`） |

时间戳、作者、提交信息全部固定，构建结果可复现。测试约 140 条，覆盖版本排序、
区间代数、通告解析（含中文、硬换行、分节、否定、噪声掩码）、端到端核对、报告与 CLI。

## 目录

```
src/vulnrange/
  versions/    版本解析、排序、区间集合
  advisory/    通告文本 → 声明（含证据与置信度）
  repo/        git 只读封装
  analysis/    发布线索引、修复提交核对、范围求解
  report/      text / markdown / json 渲染
  cli.py       命令行入口与退出码
tools/build_fixtures.py   测试仓库生成器
examples/                 演示通告与脚本
tests/                    测试
```

## 已知限制

* 通告文本解析基于规则，不调用语言模型：写法极其古怪的长尾仍会落到 `UNPARSED`，
  此时报告会明确说"没读懂"，而不是给出错误范围。
* 受影响性假设"修复之前的每个发布都受影响"，除非通告给出 `introduced` 版本。
  若漏洞实际只影响部分配置，仓库历史无法得知。
* 只读 git：需要能访问仓库历史。浅克隆缺少 patch 内容时无法匹配回移。
* 通告里没有 CVE/GHSA 号、也没有修复提交时，搜索会退化到关键词匹配甚至会放弃；
  这种情况下可信度会被限制在 0.5。
