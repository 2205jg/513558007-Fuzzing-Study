Welcome to Fuzzgoat
===================

This C program has been deliberately backdoored with several memory corruption bugs to test the efficacy of fuzzers and other analysis tools. Each vulnerability is clearly commented in fuzzgoat.c. Under input-files/ are files to trigger each vulnerability.

CAUTION: Do not copy any of this code - there is evil stuff in this repo.


Install AFL (American Fuzzy Lop)
------------------------

While Fuzzgoat can be attacked using any fuzzer, we like AFL. To install it:

1. Download AFL: [http://lcamtuf.coredump.cx/afl/releases/afl-latest.tgz](http://lcamtuf.coredump.cx/afl/releases/afl-latest.tgz)

2. Build AFL with `make install`

3. See the AFL quick start guide for more info: [http://lcamtuf.coredump.cx/afl/QuickStartGuide.txt](http://lcamtuf.coredump.cx/afl/QuickStartGuide.txt) 


Building Fuzzgoat
----------

Fuzzgoat builds with make. With afl-gcc in your PATH:

`make`


Running AFL
--------------------------

With afl-fuzz in your PATH and a seed file in a directory called in/

`afl-fuzz -i in -o out ./fuzzgoat @@` 

or simply:

`make afl`


Thank You
---------
Contributor: Joseph Carlos 

Fuzzgoat was adapted from udp/json-parser - we chose it because:

* Its not too big or cumbersome - ~1200 lines of C yet lots of paths for a fuzzer to dig into.
* Performance: its very fast at ~1500 execs per sec per core.
* The code is clean and very readable.

Fuzz Stati0n would like to thank the creators and maintainers of udp/json-parser. 
# 513558007 - 模糊測試專題進度 (Week 7)

## 目前進度
- [x] AFL++ 容器環境佈署成功 (Podman/Docker)
- [x] Fuzzgoat 原始碼插樁編譯完成 (afl-clang-fast)
- [x] AddressSanitizer (ASan) 版本編譯完成

## 編譯指令紀錄
```bash
# 手動插樁指令
afl-clang-fast -o fuzzgoat -I. main.c fuzzgoat.c -lm
```

## 期末專案分析紀錄 (Final Project Records)

本 repository 已保存期末專案的可重現分析資料，重點是針對
`out/default/crashes/` 中全部 65 個 AFL++ crash samples 進行
AddressSanitizer replay 與 source-level root cause analysis。

### 分析摘要

- 分析樣本數：65 個 AFL++ crash samples
- 分類結果：
  - heap-buffer-overflow: 39
  - heap-use-after-free: 16
  - invalid-free / bad-free: 9
  - segmentation-fault: 1
- Source-level stack groups: 5 groups
- 主要工具：AFL++, AddressSanitizer, addr2line, WSL/Linux

### 保留檔案

以下檔案位於 `final_project_records/`：

- `crash_analysis.csv`：65 個 crash samples 的分類摘要表
- `crash_analysis.json`：完整 replay 結果、stack frames 與 source locations
- `analyze_crashes_wsl.py`：逐一 replay crash samples 並產生分析輸出的腳本
- `regression_test_crash_corpus.py`：使用原 65 個 crash samples 驗證修補結果的回歸測試腳本
- `regression_after_patch.csv`：修補後 65 個樣本的回歸測試摘要表
- `regression_after_patch.json`：修補後完整回歸測試結果

依照提交整理需求，GitHub final records 僅保留分析資料與分析腳本；PDF、PPT、Markdown 報告檔與簡報練習文字稿不放入 repository。

## Vulnerability Fixes and Regression Testing

This branch patches the crash root causes identified from the final AFL++ crash
corpus analysis and validates the fixes with the original 65 crash samples.

### Patched root causes

- `main.c:150`: allocate `file_size + 1` bytes and append a `NUL` terminator
  before printing file contents as a C string.
- `fuzzgoat.c:137`: remove the premature `free(*top)` path that caused
  downstream use-after-free behavior.
- `fuzzgoat.c:258`: change `value->u.object.length--` to
  `--value->u.object.length` to avoid indexing one element past the object
  values array.
- `fuzzgoat.c:276`: keep `value->u.string.ptr` at the allocated base address
  instead of decrementing it for empty strings.
- `fuzzgoat.c:293`: remove the intentional NULL pointer dereference for
  one-byte strings.
- `fuzzgoat.c:85`: add a defensive NULL guard in `default_free`.

`fuzzgoat.c:224` was treated as a downstream crash site. The practical fix is
to remove the upstream memory corruption sources rather than adding unreliable
pointer-validity checks in C.

### Regression result

Regression testing re-ran the original GitHub crash corpus:

- Total crash samples: 65
- Passed: 65
- Failed: 0
- AddressSanitizer errors after patch: 0
- Signal crashes after patch: 0

Generated files:

- `final_project_records/regression_test_crash_corpus.py`
- `final_project_records/regression_after_patch.csv`
- `final_project_records/regression_after_patch.json`

