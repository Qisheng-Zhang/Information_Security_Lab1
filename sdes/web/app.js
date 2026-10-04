/* ==========================================================================
   S-DES 网页版界面 —— 前端脚本 (纯 JavaScript, 无第三方依赖)
   所有密码学计算都在后端 (复用 sdes.core / codec / crack / client),
   前端只负责收集参数、调用 JSON 接口、渲染结果。
   ========================================================================== */

(function () {
  "use strict";

  /* ------------------------------------------------------------ 工具函数 --- */

  const $ = (id) => document.getElementById(id);

  /** 统一的后端调用: 成功返回 data, 失败抛出带中文原因的 Error。 */
  async function api(path, payload) {
    const opts = {
      method: payload === undefined ? "GET" : "POST",
      headers: { "Content-Type": "application/json" },
    };
    if (payload !== undefined) opts.body = JSON.stringify(payload);
    let resp;
    try {
      resp = await fetch(path, opts);
    } catch (err) {
      throw new Error("无法连接本地服务, 请确认 python -m sdes.webapp 仍在运行");
    }
    let body;
    try {
      body = await resp.json();
    } catch (err) {
      throw new Error(`服务返回了非 JSON 内容 (HTTP ${resp.status})`);
    }
    if (!body.ok) throw new Error(body.error || `请求失败 (HTTP ${resp.status})`);
    return body.data;
  }

  const GET = (path) => api(path);

  /** 去掉位串中的空白与下划线。 */
  const cleanBits = (s) => String(s || "").replace(/[\s_]/g, "");

  /** 给按钮加“忙”状态, 防止重复点击。 */
  async function withBusy(button, fn, statusText) {
    if (!button) return fn();
    const old = button.textContent;
    button.disabled = true;
    if (statusText) setStatus("busy", statusText);
    try {
      const out = await fn();
      setStatus("ok", "就绪");
      return out;
    } catch (err) {
      setStatus("bad", "出错");
      throw err;
    } finally {
      button.disabled = false;
      button.textContent = old;
    }
  }

  function setStatus(kind, text) {
    const chip = $("status-chip");
    if (!chip) return;
    chip.textContent = text;
    chip.className = "chip " + (kind === "ok" ? "ok" : kind === "bad" ? "bad" : kind === "busy" ? "busy" : "");
  }

  function showError(target, err) {
    if (typeof target === "string") target = $(target);
    if (!target) { alert("错误: " + err.message); return; }
    target.classList.remove("hidden");
    target.innerHTML = `<span class="badge bad">错误</span> ${escapeHtml(err.message)}`;
  }

  function escapeHtml(text) {
    return String(text).replace(/[&<>"']/g, (c) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  }

  /** 生成表格 HTML。 */
  function table(headers, rows, rowClassFn) {
    const head = headers.map((h) => `<th>${escapeHtml(h)}</th>`).join("");
    const body = rows.map((cells, i) => {
      const cls = rowClassFn ? rowClassFn(cells, i) : "";
      const tds = cells.map((c) => `<td>${c}</td>`).join("");
      return `<tr class="${cls}">${tds}</tr>`;
    }).join("");
    return `<thead><tr>${head}</tr></thead><tbody>${body}</tbody>`;
  }

  function download(filename, text) {
    const blob = new Blob([text], { type: "text/csv;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    setTimeout(() => URL.revokeObjectURL(url), 3000);
  }

  async function copyText(text) {
    try {
      await navigator.clipboard.writeText(text);
      return true;
    } catch (err) {
      const ta = document.createElement("textarea");
      ta.value = text;
      document.body.appendChild(ta);
      ta.select();
      const ok = document.execCommand("copy");
      document.body.removeChild(ta);
      return ok;
    }
  }

  function setProgress(bar, ratio, indeterminate) {
    if (!bar) return;
    if (indeterminate) {
      bar.classList.add("indeterminate");
      return;
    }
    bar.classList.remove("indeterminate");
    bar.style.width = Math.max(0, Math.min(1, ratio)) * 100 + "%";
  }

  /* ------------------------------------------------------------- 页签切换 --- */

  function initTabs() {
    const tabs = document.querySelectorAll(".tab");
    tabs.forEach((tab) => {
      tab.addEventListener("click", () => {
        tabs.forEach((t) => t.classList.toggle("active", t === tab));
        document.querySelectorAll(".panel").forEach((p) => {
          p.classList.toggle("active", p.id === tab.dataset.panel);
        });
        window.scrollTo({ top: 0, behavior: "smooth" });
      });
    });
  }

  /* ============================================================ 第 1 关 === */

  function initLevel1() {
    const ptInput = $("l1-pt"), keyInput = $("l1-key");
    const stepsBox = $("l1-steps"), stepsTable = $("l1-steps-table");

    function clearResults() {
      ["l1-ct-hex", "l1-ct", "l1-k1", "l1-k2"].forEach((id) => { $(id).textContent = "—"; });
      stepsBox.classList.add("hidden");
    }

    // 加密时输出的是密文, 解密时输出的是明文 —— 标题要跟着切换,
    // 否则解密结果会被标成"密文", 截图放进报告会自相矛盾。
    function setOutputLabels(decrypting) {
      $("l1-out-hex-label").textContent = decrypting ? "明文 (2-bit hex)" : "密文 (2-bit hex)";
      $("l1-out-bits-label").textContent = decrypting ? "明文 (8-bit)" : "密文 (8-bit)";
    }

    // 加密与解密的响应字段不同(密文在 ciphertext/ciphertext_hex,
    // 明文在 plaintext/plaintext_hex), 必须按方向取, 否则解密时会在
    // "明文"框里显示输入的密文 —— 会出现 hex=8C 而 8-bit=10010111 的自相矛盾。
    function fill(result, decrypting) {
      const hex = decrypting ? result.plaintext_hex : result.ciphertext_hex;
      const bits = decrypting ? result.plaintext : result.ciphertext;
      $("l1-ct-hex").textContent = hex ?? "—";
      $("l1-ct").textContent = bits ?? "—";
      $("l1-k1").textContent = result.k1 || "—";
      $("l1-k2").textContent = result.k2 || "—";
    }

    function renderSteps(steps) {
      const rows = Object.entries(steps).map(([k, v]) =>
        [`<span class="k">${escapeHtml(k)}</span>`, `<b>${escapeHtml(v)}</b>`]);
      stepsTable.innerHTML = table(["步骤", "位串"], rows);
      stepsBox.classList.remove("hidden");
    }

    $("l1-enc").addEventListener("click", () => withBusy($("l1-enc"), async () => {
      try {
        const data = await api("/api/encrypt", {
          plaintext: ptInput.value, key: keyInput.value,
        });
        setOutputLabels(false);
        fill(data, false);
        renderSteps(data.steps);
      } catch (err) { clearResults(); showError("l1-steps", err); }
    }, "加密中"));

    $("l1-dec").addEventListener("click", () => withBusy($("l1-dec"), async () => {
      try {
        const data = await api("/api/decrypt", {
          ciphertext: ptInput.value, key: keyInput.value,
        });
        setOutputLabels(true);
        fill(data, true);
        stepsBox.classList.add("hidden");
      } catch (err) { clearResults(); showError("l1-steps", err); }
    }, "解密中"));

    $("l1-trace").addEventListener("click", () => withBusy($("l1-trace"), async () => {
      try {
        const data = await api("/api/encrypt", {
          plaintext: ptInput.value, key: keyInput.value,
        });
        setOutputLabels(false);
        fill(data, false);
        renderSteps(data.steps);
      } catch (err) { clearResults(); showError("l1-steps", err); }
    }, "计算中"));

    $("l1-rand").addEventListener("click", () => {
      const p = Math.floor(Math.random() * 256).toString(2).padStart(8, "0");
      const k = Math.floor(Math.random() * 1024).toString(2).padStart(10, "0");
      ptInput.value = p;
      keyInput.value = k;
      clearResults();
    });

    $("l1-clear").addEventListener("click", () => {
      ptInput.value = "";
      keyInput.value = "";
      clearResults();
    });
  }

  /* ============================================================ 第 2 关 === */

  function initLevel2() {
    const csv = $("l2-csv"), remote = $("l2-remote"), status = $("l2-status"), result = $("l2-result");
    let lastCsv = "";

    $("l2-gen").addEventListener("click", () => withBusy($("l2-gen"), async () => {
      try {
        const key = cleanBits($("l2-key").value);
        const data = await api("/api/vectors", {
          count: Number($("l2-count").value || 200),
          key: key || null,
        });
        lastCsv = data.csv;
        csv.value = data.csv;
        status.textContent =
          `已生成 ${data.count} 条测试向量 (随机种子 ${data.seed}, 密钥${key ? "固定为 " + key : "随机"})。` +
          ` 可下载后发给搭档, 或用对方的文件做比对。`;
        result.innerHTML = "";
      } catch (err) { status.textContent = "生成失败: " + err.message; }
    }, "生成中"));

    $("l2-download").addEventListener("click", () => {
      if (!csv.value.trim()) { alert("请先生成或粘贴测试向量。"); return; }
      download(`sdes_vectors_${new Date().toISOString().slice(0, 10)}.csv`, csv.value);
    });

    $("l2-copy").addEventListener("click", async () => {
      if (!csv.value.trim()) { alert("请先生成或粘贴测试向量。"); return; }
      const ok = await copyText(csv.value);
      status.textContent = ok ? "已复制到剪贴板。" : "复制失败, 请手动选择文本复制。";
    });

    $("l2-clear").addEventListener("click", () => {
      csv.value = "";
      remote.value = "";
      lastCsv = "";
      result.innerHTML = "";
      status.textContent = "尚未生成。";
    });

    $("l2-file").addEventListener("change", (ev) => {
      const file = ev.target.files && ev.target.files[0];
      if (!file) return;
      const reader = new FileReader();
      reader.onload = () => {
        remote.value = String(reader.result || "");
        status.textContent = `已载入 ${file.name} (${remote.value.split(/\r?\n/).filter(Boolean).length} 行)。`;
      };
      reader.readAsText(file, "utf-8");
    });

    $("l2-compare").addEventListener("click", () => withBusy($("l2-compare"), async () => {
      const local = lastCsv || csv.value;
      if (!local.trim()) { result.innerHTML = `<span class="badge bad">提示</span> 请先生成本机测试向量。`; return; }
      if (!remote.value.trim()) { result.innerHTML = `<span class="badge bad">提示</span> 请先选择或粘贴对方的 CSV。`; return; }
      try {
        const data = await api("/api/vectors/compare", { csv_a: local, csv_b: remote.value });
        const badge = data.same
          ? `<span class="badge ok">一致 ${data.total}/${data.total} 行</span>`
          : `<span class="badge bad">不一致</span>`;
        let html = `${badge} 本机 ${data.local_rows} 行, 对方 ${data.remote_rows} 行。`;
        html += data.same
          ? " 两套程序对相同明文与密钥得到完全相同的密文, 交叉测试通过 ✓"
          : ` 存在 ${data.mismatch_count} 处差异 (最多显示前 20 处):`;
        if (!data.same && data.mismatches.length) {
          html += `<table class="data-table mono">` + table(
            ["#", "本机 (pt,key,ct)", "对方 (pt,key,ct)"],
            data.mismatches.map((m) => [
              m.index,
              m.local ? escapeHtml(m.local.join(",")) : "<i>缺失</i>",
              m.remote ? escapeHtml(m.remote.join(",")) : "<i>缺失</i>",
            ])) + "</table>";
        }
        result.innerHTML = html;
      } catch (err) {
        result.innerHTML = `<span class="badge bad">错误</span> ${escapeHtml(err.message)}`;
      }
    }, "比对中"));
  }

  /* ============================================================ 第 3 关 === */

  function initLevel3() {
    const keyInput = $("l3-key"), textInput = $("l3-text"), hexInput = $("l3-hex");
    const info = $("l3-info"), log = $("l3-log");

    $("l3-enc").addEventListener("click", () => withBusy($("l3-enc"), async () => {
      try {
        const data = await api("/api/text/encrypt", {
          text: textInput.value,
          key: keyInput.value,
          encoding: $("l3-encoding").value,
        });
        hexInput.value = data.ciphertext_hex;
        info.textContent =
          `${data.byte_count} 字节 -> ${data.block_count} 个 S-DES 分组` +
          (data.padded_bits ? ` (补 ${data.padded_bits} 个 0 bit)` : " (无需补位)") +
          `, 密文 ${data.ciphertext_hex.length} 个十六进制字符。`;
      } catch (err) { info.textContent = "加密失败: " + err.message; }
    }, "加密中"));

    $("l3-dec").addEventListener("click", () => withBusy($("l3-dec"), async () => {
      try {
        const data = await api("/api/text/decrypt", {
          hex: hexInput.value, key: keyInput.value, encoding: $("l3-encoding").value,
        });
        textInput.value = data.text;
        info.textContent = `已解密 ${data.hex.length / 2} 字节。`;
      } catch (err) { info.textContent = "解密失败: " + err.message; }
    }, "解密中"));

    $("l3-swap").addEventListener("click", () => {
      if (!hexInput.value.trim()) { alert("密文为空。"); return; }
      textInput.value = hexInput.value.trim();
      info.textContent = "已把密文填入明文框, 此时再点“加密”会得到二次加密的结果。";
    });

    $("l3-send").addEventListener("click", () => withBusy($("l3-send"), async () => {
      try {
        const data = await api("/api/tcp/send", {
          host: $("l3-host").value,
          port: Number($("l3-port").value || 50007),
          key: keyInput.value,
          text: textInput.value,
        });
        log.className = "log mono " + (data.ok ? "ok" : "bad");
        log.textContent = data.log.join("\n");
        hexInput.value = data.ciphertext_hex;
      } catch (err) {
        log.className = "log mono bad";
        log.textContent = "通信失败: " + err.message +
          "\n\n请先在另一个终端启动服务端: python -m sdes.server";
      }
    }, "通信中"));
  }

  /* ============================================================ 第 4 关 === */

  function initLevel4() {
    const pairsInput = $("l4-pairs"), status = $("l4-status"), bar = $("l4-bar");
    const keysBox = $("l4-keys");

    /** 把 "10010111,00111000" 文本解析成 [[pt, ct], ...]。 */
    function parsePairs(text) {
      const pairs = [];
      for (const raw of String(text).split(/[\n;]+/)) {
        const line = raw.trim();
        if (!line) continue;
        const parts = line.split(/[,\s]+/).filter(Boolean);
        if (parts.length !== 2) throw new Error(`格式错误: “${line}”, 应为 明文,密文`);
        pairs.push([cleanBits(parts[0]), cleanBits(parts[1])]);
      }
      if (!pairs.length) throw new Error("至少需要一组明文-密文对");
      return pairs;
    }

    function reset() {
      ["l4-count", "l4-tried", "l4-elapsed", "l4-rate"].forEach((id) => { $(id).textContent = "—"; });
      keysBox.innerHTML = "";
      setProgress(bar, 0);
    }

    $("l4-start").addEventListener("click", () => withBusy($("l4-start"), async () => {
      let pairs;
      try {
        pairs = parsePairs(pairsInput.value);
      } catch (err) {
        status.textContent = "输入错误: " + err.message;
        reset();
        return;
      }
      setProgress(bar, 0.35, true);
      status.textContent = `正在穷举 1024 个密钥… (${pairs.length} 组明密文对)`;
      try {
        const data = await api("/api/crack", {
          pairs,
          threaded: $("l4-threaded").checked,
          workers: Number($("l4-workers").value || 8),
          chunk: Number($("l4-chunk").value || 64),
        });
        setProgress(bar, 1);
        $("l4-count").textContent = `${data.key_count} 个`;
        $("l4-tried").textContent = `${data.tried} 个`;
        $("l4-elapsed").textContent = `${data.elapsed_ms.toFixed(3)} ms`;
        $("l4-rate").textContent = `${Math.round(data.rate).toLocaleString()} 次/秒`;
        keysBox.innerHTML = data.keys.map((k) => `<span class="key">${k}</span>`).join("");
        status.textContent =
          `破解完成: ${pairs.length} 组明密文对留下 ${data.key_count} 个候选密钥` +
          ` (${data.threaded ? `多线程 ${data.workers} 线程 / ${data.chunks} 个任务块` : "单线程"})。` +
          (pairs.length === 1 ? " 单组明文-密文平均留下约 4 个候选, 再加一组即可唯一确定。" : "");
      } catch (err) {
        setProgress(bar, 0);
        status.textContent = "破解失败: " + err.message;
        reset();
      }
    }, "破解中"));

    $("l4-rand").addEventListener("click", () => withBusy($("l4-rand"), async () => {
      try {
        const pt = Math.floor(Math.random() * 256);
        const key = Math.floor(Math.random() * 1024);
        const data = await api("/api/encrypt", {
          plaintext: pt.toString(2).padStart(8, "0"),
          key: key.toString(2).padStart(10, "0"),
        });
        reset();
        pairsInput.value = `${data.plaintext},${data.ciphertext}`;
        keysBox.innerHTML = `<span class="key truth">真钥匙 ${data.key} (仅演示用, 破解时程序并不知道)</span>`;
        status.textContent = `已随机生成一组明密文对 (明文 ${data.plaintext}, 密文 ${data.ciphertext})。点击“开始破解”即可看到候选密钥。`;
      } catch (err) {
        status.textContent = "生成失败: " + err.message;
      }
    }, "生成中"));

    $("l4-clear").addEventListener("click", () => {
      pairsInput.value = "";
      reset();
      status.textContent = "就绪。";
    });
  }

  /* ============================================================ 第 5 关 === */

  function initLevel5() {
    const status = $("l5-status"), bar = $("l5-bar"), body = $("l5-body");

    $("l5-run").addEventListener("click", () => withBusy($("l5-run"), async () => {
      setProgress(bar, 0.5, true);
      status.textContent = "正在枚举 1024 × 256 = 262144 个 (密钥, 明文) 组合…";
      try {
        const data = await api("/api/collisions", { sample: Number($("l5-sample").value || 0) });
        setProgress(bar, 1);
        status.textContent =
          `全空间分析完成: 密钥空间 ${data.key_space}, 明文空间 ${data.block_space}, ` +
          `共枚举 ${data.total_pairs.toLocaleString()} 个组合, 每个明文平均 ${data.distinct_per_pt} 个不同密文。`;
        $("l5-max").textContent = `${data.max_bucket} 个密钥`;
        $("l5-avg").textContent = `${data.avg_candidates_per_cipher.toFixed(3)} 个`;

        const bucketRows = data.buckets.map((b) => {
          const ratio = (b.count / data.total_pairs * 100 * 4).toFixed(1);
          return [b.size, b.count, `<div style="background:var(--brand);height:9px;width:${Math.min(100, Number(ratio))}%;border-radius:4px"></div>`];
        });
        $("l5-buckets").innerHTML = table(["桶大小 (密钥个数)", "出现次数", "占比"], bucketRows);

        const s = data.sample;
        $("l5-sample-info").innerHTML =
          `明文 <b class="mono">${s.plaintext}</b>: 共有 ${s.multi_cipher_count} 个密文能被 2 个以上密钥解出。` +
          ` 下面前 8 条按 “能解出的密钥个数” 降序排列。`;
        $("l5-cases").innerHTML = table(
          ["密文", "能解出该密文的密钥 (个数)"],
          s.cases.map((c) => [
            `<b>${c.ct}</b>`,
            c.keys.map((k) => `<span class="key">${k}</span>`).join(" ") + ` <span class="badge warn">${c.keys.length}</span>`,
          ]));
        body.classList.remove("hidden");
      } catch (err) {
        setProgress(bar, 0);
        status.textContent = "分析失败: " + err.message;
        body.classList.add("hidden");
      }
    }, "分析中"));

    $("l5-report").addEventListener("click", () => withBusy($("l5-report"), async () => {
      try {
        const data = await GET("/api/report");
        const pre = $("l5-report-text");
        pre.textContent = data.text;
        pre.classList.remove("hidden");
      } catch (err) {
        $("l5-status").textContent = "报告获取失败: " + err.message;
      }
    }, "生成报告"));
  }

  /* ========================================================== 算法规格 === */

  async function initSpec() {
    try {
      const meta = await GET("/api/meta");
      $("version-chip").textContent = "v" + meta.version;

      const label = {
        P10: "P10 密钥扩展置换 (10→10)",
        P8: "P8 密钥压缩置换 (10→8)",
        IP: "IP 初始置换 (8→8)",
        IP_INV: "IP⁻¹ 最终置换 (8→8)",
        EP: "EPBox 扩展置换 (4→8)",
        SPBOX: "SPBox (4→4)",
      };
      const rows = Object.keys(label).map((k) =>
        [label[k], `<b>${(meta.tables[k] || []).join(", ")}</b>`]);
      $("spec-tables").innerHTML = table(["转换表", "取值"], rows);

      /** 渲染一个 S 盒为 4×4 表格。 */
      function sboxHtml(box) {
        const head = ["行\\列", "00", "01", "10", "11"];
        const rows = box.map((row, i) =>
          [["00", "01", "10", "11"][i], ...row.map((v) => `<b>${v.toString(2).padStart(2, "0")}</b>`)]);
        return `<table class="data-table mono">${table(head, rows)}</table>`;
      }
      $("spec-sbox").innerHTML =
        `<div><h3>SBox1 (与标准 S-DES 的 S0 相同)</h3>${sboxHtml(meta.tables.SBOX1)}</div>` +
        `<div><h3>SBox2 (与标准 S1 不同 · 以此处为准)</h3>${sboxHtml(meta.tables.SBOX2)}</div>`;
    } catch (err) {
      $("spec-tables").innerHTML = `<tr><td>规格表加载失败: ${escapeHtml(err.message)}</td></tr>`;
    }
  }

  /* ---------------------------------------------------------------- 启动 --- */

  document.addEventListener("DOMContentLoaded", () => {
    initTabs();
    initLevel1();
    initLevel2();
    initLevel3();
    initLevel4();
    initLevel5();
    initSpec();

    // 第 4 关默认给一组自洽的明密文对
    api("/api/encrypt", { plaintext: "10010111", key: "1010000010" })
      .then((d) => { $("l4-pairs").value = `${d.plaintext},${d.ciphertext}`; })
      .catch(() => { /* 后端没起来时保持占位内容 */ });
  });
})();
