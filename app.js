const CHARSET = ["魑", "魅", "魍", "魉"]; // base4 digits: 0..3
const REVERSE = new Map(CHARSET.map((ch, i) => [ch, i]));

const SALT_LEN = 16;
const IV_LEN = 12; // AES-GCM recommended nonce length
const KEY_BITS = 256;

const MODES = {
  standard: { id: 0, name: "standard", label: "标准密文（兼容）", saltLen: SALT_LEN, ivLen: IV_LEN },
  // 12-byte salt (96-bit) 使输出更短；权衡：盐熵从 2^128 降到 2^96，但对大多数 PBKDF2 场景仍足够
  compact: { id: 1, name: "compact", label: "短密文（减少长度）", saltLen: 12, ivLen: IV_LEN },
};
const MODE_BY_ID = new Map(Object.values(MODES).map(m => [m.id, m]));

const hasDOM = typeof document !== "undefined";
const $ = hasDOM ? (id) => document.getElementById(id) : () => null;
const statusEl = hasDOM ? $("status") : null;

function setStatus(msg, kind = "info") {
  if (!statusEl) return;
  const prefix = kind === "error" ? "[ERROR] " : kind === "ok" ? "[OK] " : "[INFO] ";
  statusEl.textContent = prefix + msg;
}

function assertCipherAlphabet(str) {
  for (const ch of str) {
    if (!REVERSE.has(ch)) {
      throw new Error(`密文含非法字符：${JSON.stringify(ch)}（只允许 魑魅魍魉）`);
    }
  }
}

function bytesToBase4Chars(bytes) {
  // Each byte -> 4 base4 digits (2 bits each)
  let out = "";
  for (const b of bytes) {
    out += CHARSET[(b >> 6) & 3];
    out += CHARSET[(b >> 4) & 3];
    out += CHARSET[(b >> 2) & 3];
    out += CHARSET[b & 3];
  }
  return out;
}

function base4CharsToBytes(str) {
  str = str.trim();
  assertCipherAlphabet(str);
  if (str.length % 4 !== 0) {
    throw new Error("密文长度不合法：必须是 4 的倍数（每 4 个字符还原 1 个字节）");
  }

  const out = new Uint8Array(str.length / 4);
  for (let i = 0, j = 0; i < str.length; i += 4, j++) {
    const d0 = REVERSE.get(str[i]);
    const d1 = REVERSE.get(str[i + 1]);
    const d2 = REVERSE.get(str[i + 2]);
    const d3 = REVERSE.get(str[i + 3]);
    out[j] = (d0 << 6) | (d1 << 4) | (d2 << 2) | d3;
  }
  return out;
}

function concatBytes(...parts) {
  let total = 0;
  for (const p of parts) total += p.length;
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

function getModeConfig(name = "standard") {
  return MODES[name] || MODES.standard;
}

async function deriveKey(passphrase, salt, iterations) {
  const enc = new TextEncoder();
  const passKey = await crypto.subtle.importKey(
    "raw",
    enc.encode(passphrase),
    { name: "PBKDF2" },
    false,
    ["deriveKey"]
  );

  return crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt,
      iterations,
      hash: "SHA-256",
    },
    passKey,
    { name: "AES-GCM", length: KEY_BITS },
    false,
    ["encrypt", "decrypt"]
  );
}

async function encryptText(plainText, passphrase, iterations, modeName = "standard") {
  const mode = getModeConfig(modeName);
  const enc = new TextEncoder();
  const salt = crypto.getRandomValues(new Uint8Array(mode.saltLen));
  const iv = crypto.getRandomValues(new Uint8Array(mode.ivLen));
  const key = await deriveKey(passphrase, salt, iterations);

  const cipherBuf = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    enc.encode(plainText)
  );

  const cipherBytes = new Uint8Array(cipherBuf);
  const header = new Uint8Array([mode.id]);
  const payload = concatBytes(header, salt, iv, cipherBytes);
  return bytesToBase4Chars(payload);
}

async function decryptText(cipherChars, passphrase, iterations) {
  const payload = base4CharsToBytes(cipherChars);

  const parsed = parsePayload(payload);

  const key = await deriveKey(passphrase, parsed.salt, iterations);

  let plainBuf;
  try {
    plainBuf = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: parsed.iv },
      key,
      parsed.cipherBytes
    );
  } catch {
    // AES-GCM 校验失败通常是口令错误或密文被篡改
    throw new Error("解密失败：口令错误或密文已损坏/被篡改");
  }

  const dec = new TextDecoder();
  return dec.decode(plainBuf);
}

function getIterations() {
  const raw = hasDOM ? $("iterations")?.value : undefined;
  const n = raw !== undefined ? Number(raw) : NaN;
  if (!Number.isFinite(n) || n < 10000) throw new Error("PBKDF2 迭代次数需为 >= 10000 的数字");
  return Math.floor(n);
}

function getSelectedModeName() {
  if (!hasDOM) return "standard";
  const val = $("mode")?.value;
  return val && MODES[val] ? val : "standard";
}

function normalizeCipherInput(s) {
  // 允许用户粘贴时带空格/换行：去掉所有空白
  return s.replace(/\s+/g, "");
}

function parsePayload(payload) {
  if (payload.length >= 1) {
    const mode = MODE_BY_ID.get(payload[0]);
    if (mode) {
      const body = payload.slice(1);
      if (body.length < mode.saltLen + mode.ivLen) {
        throw new Error("密文长度不足或已损坏（模式 " + mode.name + "）");
      }
      return {
        mode,
        salt: body.slice(0, mode.saltLen),
        iv: body.slice(mode.saltLen, mode.saltLen + mode.ivLen),
        cipherBytes: body.slice(mode.saltLen + mode.ivLen),
      };
    }
  }

  if (payload.length < SALT_LEN + IV_LEN) {
    throw new Error("密文过短或格式未知（需包含 salt + iv + ciphertext）");
  }

  return {
    mode: MODES.standard,
    salt: payload.slice(0, SALT_LEN),
    iv: payload.slice(SALT_LEN, SALT_LEN + IV_LEN),
    cipherBytes: payload.slice(SALT_LEN + IV_LEN),
  };
}

async function onEncrypt() {
  const plain = $("plainIn").value;
  const pass = $("passEnc").value;
  if (!plain) throw new Error("请输入明文");
  if (!pass) throw new Error("请输入口令");
  const iterations = getIterations();
  const modeName = getSelectedModeName();
  const mode = getModeConfig(modeName);

  const cipher = await encryptText(plain, pass, iterations, modeName);
  $("cipherOut").value = cipher;
  $("cipherIn").value = cipher; // 方便直接解密测试
  setStatus(`加密完成（${mode.label}）：输出长度 ${cipher.length}（只含 魑魅魍魉）`, "ok");
}

async function onDecrypt() {
  const cipherRaw = $("cipherIn").value;
  const pass = $("passDec").value;
  if (!cipherRaw) throw new Error("请输入密文");
  if (!pass) throw new Error("请输入口令");
  const iterations = getIterations();

  const cipher = normalizeCipherInput(cipherRaw);
  const plain = await decryptText(cipher, pass, iterations);
  $("plainOut").value = plain;
  setStatus("解密完成。", "ok");
}

async function onCopyCipher() {
  const text = $("cipherOut").value;
  if (!text) throw new Error("没有可复制的密文");
  await navigator.clipboard.writeText(text);
  setStatus("已复制密文到剪贴板。", "ok");
}

async function onSelfTest() {
  if (!hasDOM) throw new Error("自检仅在浏览器环境可用");
  const iterations = getIterations();
  const pass = "test-passphrase";
  const plain = `自检文本\n时间: ${new Date().toISOString()}\n随机: ${crypto.getRandomValues(new Uint32Array(1))[0]}`;
  const modeName = getSelectedModeName();
  const mode = getModeConfig(modeName);

  const cipher = await encryptText(plain, pass, iterations, modeName);

  // 验证字符集
  assertCipherAlphabet(cipher);

  const back = await decryptText(cipher, pass, iterations);
  if (back !== plain) throw new Error("自检失败：解密结果与原文不一致");

  setStatus(`自检通过（${mode.label}）。密文长度=${cipher.length}，示例密文前 64 字：\n${cipher.slice(0, 64)}...`, "ok");
}

function bind() {
  $("btnEncrypt").addEventListener("click", () => onEncrypt().catch(e => setStatus(e.message, "error")));
  $("btnDecrypt").addEventListener("click", () => onDecrypt().catch(e => setStatus(e.message, "error")));
  $("btnCopyCipher").addEventListener("click", () => onCopyCipher().catch(e => setStatus(e.message, "error")));
  $("btnSelfTest").addEventListener("click", () => onSelfTest().catch(e => setStatus(e.message, "error")));

  $("btnEncClear").addEventListener("click", () => {
    $("plainIn").value = "";
    $("passEnc").value = "";
    $("cipherOut").value = "";
    setStatus("已清空加密区。");
  });

  $("btnDecClear").addEventListener("click", () => {
    $("cipherIn").value = "";
    $("passDec").value = "";
    $("plainOut").value = "";
    setStatus("已清空解密区。");
  });
}

if (hasDOM) {
  bind();
  setStatus("准备就绪。你可以先点击“运行自检”。");
}

export {
  CHARSET,
  REVERSE,
  MODES,
  getModeConfig,
  parsePayload,
  encryptText,
  decryptText,
  bytesToBase4Chars,
  base4CharsToBytes,
  normalizeCipherInput,
  assertCipherAlphabet,
};
