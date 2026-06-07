# 期末專案報告：使用 AFL++ 對 Fuzzgoat 進行模糊測試與漏洞分析

- 學號：513558007
- 專案名稱：使用 AFL++ 對 Fuzzgoat 進行自動化模糊測試與漏洞分析
- GitHub Repository：https://github.com/2205jg/513558007-Fuzzing-Study
- 報告日期：2026-06-06
- 分析範圍：GitHub 上 `out/default/crashes/` 內全部 AFL++ crash samples

## 一、專案摘要

本專題以 Fuzzgoat 作為測試目標，使用 AFL++ 產生 crash corpus，再以 AddressSanitizer 版本的 `fuzzgoat_ASAN` 逐一回放 GitHub 上的 crash samples，分析每個樣本的錯誤類型、訊號、stack trace 與對應原始碼位置。

原先討論時提到 63 個樣本，但重新檢查 GitHub repository 後，實際存在 65 個 `id:*` crash files。因此本報告分析全部 65 個樣本，沒有排除 `id:000000` 或 `id:000003`。

## 二、GitHub 活動紀錄

| 項目 | 內容 |
| --- | --- |
| Repository | https://github.com/2205jg/513558007-Fuzzing-Study |
| 主要 branch | master |
| 學生提交數 | 2 commits by 2205jg |
| 最新提交 | `c3da5bf`：上傳 65 個 crash samples 與 `fuzzgoat_ASAN` |
| 進度提交 | `003e4b3`：更新 README，記錄 AFL++ 與 AddressSanitizer 建置進度 |

## 三、分析方法

1. 將 GitHub repository clone 到 WSL/Linux 檔案系統，避免 Windows 無法處理 AFL++ 檔名中的冒號。
2. 對 `out/default/crashes/id:*` 中每個樣本執行 `fuzzgoat_ASAN <sample>`。
3. 擷取 AddressSanitizer 錯誤類型、exit code、AFL++ signal、payload size、SHA-256 與 stack trace。
4. 因 AddressSanitizer 未自動顯示完整 source symbol，額外使用 `addr2line` 將 binary offset 對應到原始碼行號。
5. 依錯誤類型與 source-level stack location 分群，再挑選代表樣本做根因分析。

## 四、整體分析結果

| 分類 | 樣本數 | 說明 |
| --- | --- | --- |
| heap-buffer-overflow | 39 | 讀取超出 heap 配置範圍，主要集中在 `main.c:150` |
| heap-use-after-free | 16 | 釋放後仍使用 heap 物件，主要集中在 `fuzzgoat.c:643` |
| invalid-free / bad-free | 9 | 釋放非合法 malloc 起始位址，主要集中在 `fuzzgoat.c:85` |
| segmentation-fault | 1 | 記憶體狀態錯亂後產生 `SEGV` |

| AFL++ signal | 樣本數 |
| --- | --- |
| sig:06 | 30 |
| sig:11 | 35 |

本次 replay 共形成 5 個 source-level stack groups。

## 五、代表樣本根因分析

| 樣本 | AddressSanitizer 類型 | 分類 | 主要位置 | 根因說明 |
| --- | --- | --- | --- | --- |
| id:000000 | attempting | invalid-free / bad-free | default_free at /src/fuzzgoat.c:85; main at /src/main.c:166; new_value at /src/fuzzgoat.c:99 | 此樣本觸發不合法釋放，執行路徑最後進入 `default_free`，但傳入的位址並不是合法的 `malloc` 起始位址。 |
| id:000003 | heap-buffer-overflow | heap-buffer-overflow | main at /src/main.c:150; main at /src/main.c:129 | `main.c` 只配置 `file_size` 大小的 buffer，卻直接用 `%s` 當作 C 字串輸出，缺少結尾 `NUL`，造成越界讀取。 |
| id:000014 | heap-use-after-free | heap-use-after-free | json_parse_ex at /src/fuzzgoat.c:643; json_parse at /src/fuzzgoat.c:1073; main at /src/main.c:156 | 此樣本進入 `json_parse_ex` 後，因 Fuzzgoat 內建的 `free(*top)` 漏洞路徑，後續仍使用已被釋放的 heap 物件。 |
| id:000016 | heap-buffer-overflow | heap-buffer-overflow | json_value_free at /src/fuzzgoat.c:258; main at /src/main.c:166; new_value at /src/fuzzgoat.c:99 | `json_value_free` 中使用 `value->u.object.length--`，先取用原本長度再遞減，造成 object values 越界存取。 |
| id:000027 | SEGV | segmentation-fault | json_value_free at /src/fuzzgoat.c:224; main at /src/main.c:166 | 釋放流程中的物件狀態已被破壞，進入 `json_value_free` 後發生 `SEGV`，屬於記憶體狀態錯亂後的崩潰。 |

## 六、已解決問題

| 問題 | 處理方式 | 結果 |
| --- | --- | --- |
| Windows 無法 checkout AFL++ crash 檔名 | 改在 WSL/Linux 檔案系統內 clone repository | 65 個樣本皆可正常回放 |
| AddressSanitizer stack trace 缺少 source line | 使用 `addr2line` 對 `fuzzgoat_ASAN` offset 做 symbolication | 成功定位到 `main.c` 與 `fuzzgoat.c` |
| 樣本數與預期 63 不一致 | 重新以 Git tree 與實際檔案統計確認 | 最後採用 GitHub 上全部 65 個樣本 |
| 多個樣本重複觸發同一路徑 | 依 AddressSanitizer 類型與 source location 分群 | 整理為 4 類漏洞與 5 個 stack groups |

## 七、結論

本次 final 分析確認 GitHub 上的 crash corpus 具備可重現性，且 65 個 crash samples 並不是 65 個完全不同的漏洞，而是多個 mutated inputs 重複觸發少數幾條 vulnerable paths。因此本報告以分類與代表樣本根因分析為主，並在附錄保留全部樣本的 replay 結果，方便後續查核。

後續若要延伸，可使用 `afl-tmin` 對代表樣本最小化，修補 `main.c:150`、`fuzzgoat.c:137`、`fuzzgoat.c:258` 等路徑後，再以同一批 crash corpus 做 regression test。

## 附錄 A：全部 crash samples 分析表

| 樣本 | signal | size | AddressSanitizer 類型 | 分類 | 主要位置 |
| --- | --- | --- | --- | --- | --- |
| id:000000 | 06 | 8 | attempting | invalid-free / bad-free | default_free at /src/fuzzgoat.c:85 |
| id:000001 | 06 | 11 | attempting | invalid-free / bad-free | default_free at /src/fuzzgoat.c:85 |
| id:000002 | 06 | 2 | heap-buffer-overflow | heap-buffer-overflow | main at /src/main.c:150 |
| id:000003 | 11 | 10 | heap-buffer-overflow | heap-buffer-overflow | main at /src/main.c:150 |
| id:000004 | 06 | 8 | attempting | invalid-free / bad-free | default_free at /src/fuzzgoat.c:85 |
| id:000005 | 11 | 14 | heap-buffer-overflow | heap-buffer-overflow | main at /src/main.c:150 |
| id:000006 | 06 | 6 | heap-buffer-overflow | heap-buffer-overflow | main at /src/main.c:150 |
| id:000007 | 11 | 8 | heap-buffer-overflow | heap-buffer-overflow | main at /src/main.c:150 |
| id:000008 | 11 | 12 | heap-buffer-overflow | heap-buffer-overflow | main at /src/main.c:150 |
| id:000009 | 11 | 8 | heap-buffer-overflow | heap-buffer-overflow | main at /src/main.c:150 |
| id:000010 | 06 | 8 | heap-buffer-overflow | heap-buffer-overflow | main at /src/main.c:150 |
| id:000011 | 06 | 8 | heap-buffer-overflow | heap-buffer-overflow | main at /src/main.c:150 |
| id:000012 | 06 | 4 | heap-buffer-overflow | heap-buffer-overflow | main at /src/main.c:150 |
| id:000013 | 11 | 6 | heap-buffer-overflow | heap-buffer-overflow | main at /src/main.c:150 |
| id:000014 | 06 | 65 | heap-use-after-free | heap-use-after-free | json_parse_ex at /src/fuzzgoat.c:643 |
| id:000015 | 11 | 12 | heap-buffer-overflow | heap-buffer-overflow | main at /src/main.c:150 |
| id:000016 | 11 | 17 | heap-buffer-overflow | heap-buffer-overflow | json_value_free at /src/fuzzgoat.c:258 |
| id:000017 | 06 | 68 | heap-use-after-free | heap-use-after-free | json_parse_ex at /src/fuzzgoat.c:643 |
| id:000018 | 06 | 91 | heap-use-after-free | heap-use-after-free | json_parse_ex at /src/fuzzgoat.c:643 |
| id:000019 | 06 | 319 | attempting | invalid-free / bad-free | default_free at /src/fuzzgoat.c:85 |
| id:000020 | 06 | 68 | heap-use-after-free | heap-use-after-free | json_parse_ex at /src/fuzzgoat.c:643 |
| id:000021 | 06 | 115 | attempting | invalid-free / bad-free | default_free at /src/fuzzgoat.c:85 |
| id:000022 | 06 | 776 | heap-use-after-free | heap-use-after-free | json_parse_ex at /src/fuzzgoat.c:643 |
| id:000023 | 06 | 1097 | attempting | invalid-free / bad-free | default_free at /src/fuzzgoat.c:85 |
| id:000024 | 11 | 27 | heap-buffer-overflow | heap-buffer-overflow | main at /src/main.c:150 |
| id:000025 | 11 | 8 | heap-buffer-overflow | heap-buffer-overflow | main at /src/main.c:150 |
| id:000026 | 11 | 1119 | heap-buffer-overflow | heap-buffer-overflow | main at /src/main.c:150 |
| id:000027 | 11 | 2046 | SEGV | segmentation-fault | json_value_free at /src/fuzzgoat.c:224 |
| id:000028 | 06 | 262 | heap-use-after-free | heap-use-after-free | json_parse_ex at /src/fuzzgoat.c:643 |
| id:000029 | 11 | 341 | heap-buffer-overflow | heap-buffer-overflow | main at /src/main.c:150 |
| id:000030 | 11 | 809 | heap-buffer-overflow | heap-buffer-overflow | main at /src/main.c:150 |
| id:000031 | 11 | 788 | heap-buffer-overflow | heap-buffer-overflow | main at /src/main.c:150 |
| id:000032 | 11 | 810 | heap-buffer-overflow | heap-buffer-overflow | main at /src/main.c:150 |
| id:000033 | 11 | 802 | heap-buffer-overflow | heap-buffer-overflow | main at /src/main.c:150 |
| id:000034 | 11 | 845 | heap-buffer-overflow | heap-buffer-overflow | main at /src/main.c:150 |
| id:000035 | 11 | 788 | heap-buffer-overflow | heap-buffer-overflow | main at /src/main.c:150 |
| id:000036 | 11 | 914 | heap-buffer-overflow | heap-buffer-overflow | main at /src/main.c:150 |
| id:000037 | 11 | 834 | heap-buffer-overflow | heap-buffer-overflow | main at /src/main.c:150 |
| id:000038 | 11 | 834 | heap-buffer-overflow | heap-buffer-overflow | main at /src/main.c:150 |
| id:000039 | 11 | 2168 | heap-buffer-overflow | heap-buffer-overflow | main at /src/main.c:150 |
| id:000040 | 06 | 175 | heap-use-after-free | heap-use-after-free | json_parse_ex at /src/fuzzgoat.c:643 |
| id:000041 | 06 | 9760 | heap-use-after-free | heap-use-after-free | json_parse_ex at /src/fuzzgoat.c:643 |
| id:000042 | 11 | 2140 | heap-buffer-overflow | heap-buffer-overflow | main at /src/main.c:150 |
| id:000043 | 11 | 837 | heap-buffer-overflow | heap-buffer-overflow | main at /src/main.c:150 |
| id:000044 | 11 | 712 | heap-buffer-overflow | heap-buffer-overflow | main at /src/main.c:150 |
| id:000045 | 06 | 559 | heap-use-after-free | heap-use-after-free | json_parse_ex at /src/fuzzgoat.c:643 |
| id:000046 | 11 | 844 | heap-buffer-overflow | heap-buffer-overflow | main at /src/main.c:150 |
| id:000047 | 06 | 892 | attempting | invalid-free / bad-free | default_free at /src/fuzzgoat.c:85 |
| id:000048 | 06 | 701 | heap-use-after-free | heap-use-after-free | json_parse_ex at /src/fuzzgoat.c:643 |
| id:000049 | 06 | 203 | heap-use-after-free | heap-use-after-free | json_parse_ex at /src/fuzzgoat.c:643 |
| id:000050 | 06 | 21 | attempting | invalid-free / bad-free | default_free at /src/fuzzgoat.c:85 |
| id:000051 | 06 | 467 | heap-use-after-free | heap-use-after-free | json_parse_ex at /src/fuzzgoat.c:643 |
| id:000052 | 11 | 26 | heap-buffer-overflow | heap-buffer-overflow | main at /src/main.c:150 |
| id:000053 | 11 | 810 | heap-buffer-overflow | heap-buffer-overflow | main at /src/main.c:150 |
| id:000054 | 06 | 205 | heap-use-after-free | heap-use-after-free | json_parse_ex at /src/fuzzgoat.c:643 |
| id:000055 | 06 | 1086 | heap-use-after-free | heap-use-after-free | json_parse_ex at /src/fuzzgoat.c:643 |
| id:000056 | 11 | 863 | heap-buffer-overflow | heap-buffer-overflow | main at /src/main.c:150 |
| id:000057 | 11 | 1027 | heap-buffer-overflow | heap-buffer-overflow | main at /src/main.c:150 |
| id:000058 | 11 | 810 | heap-buffer-overflow | heap-buffer-overflow | main at /src/main.c:150 |
| id:000059 | 06 | 5 | heap-buffer-overflow | heap-buffer-overflow | main at /src/main.c:150 |
| id:000060 | 11 | 303 | heap-use-after-free | heap-use-after-free | json_parse_ex at /src/fuzzgoat.c:643 |
| id:000061 | 06 | 738 | attempting | invalid-free / bad-free | default_free at /src/fuzzgoat.c:85 |
| id:000062 | 06 | 458 | heap-use-after-free | heap-use-after-free | json_parse_ex at /src/fuzzgoat.c:643 |
| id:000063 | 11 | 1574 | heap-buffer-overflow | heap-buffer-overflow | main at /src/main.c:150 |
| id:000064 | 11 | 1355 | heap-buffer-overflow | heap-buffer-overflow | main at /src/main.c:150 |

## 附錄 B：分析輸出檔

- `crash_analysis.csv`：65 個樣本的結構化分類結果
- `crash_analysis.json`：包含完整 replay result、stack frames、source locations 與 summary
