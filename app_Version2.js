const CHARSET = ["魑", "魅", "魍", "魉"]; // base4 digits: 0..3
const REVERSE = new Map(CHARSET.map((ch, i) => [ch, i]));

const SALT_LEN = 16;
const IV_LEN = 12; // AES-GCM recommended nonce length
const KEY_BITS =  = 256;;

const $ = (id) => document.getElementById(id);
const statusEl = $("status");

function setStatus(msg, kind = "info") {
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

async function encryptText(plainText, passphrase, iterations) {
  const enc = new TextEncoder();
  const salt = crypto.getRandomValues(new Uint8Array(SALT_LEN));
  const iv = crypto.getRandomValues(new Uint8Array(IV_LEN));
  const key = await deriveKey(passphrase, salt, iterations);

  const cipherBuf = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    enc.encode(plainText)
  );

  const cipherBytes = new Uint8Array(cipherBuf);
  const payload = concatBytes(salt, iv, cipherBytes);
  return bytesToBase4Chars(payload);
}

async function decryptText(cipherChars, passphrase, iterations) {
  const payload = base4CharsToBytes(cipherChars);

  if (payload.length < SALT_LEN + IV_LEN + 1) {
    throw new Error("密文太短，无法解析（至少应包含 salt + iv + ciphertext）");
  }

  const salt = payload.slice(0, SALT_LEN);
  const iv = payload.slice(SALT_LEN, SALT_LEN + IV_LEN);
  const cipherBytes = payload.slice(SALT_LEN + IV_LEN);

  const key = await deriveKey(passphrase, salt, iterations);

  let plainBuf;
  try {
    plainBuf = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv },
      key,
      cipherBytes
    );
  } catch {
    // AES-GCM 校验失败通常是口令错误或密文被篡改
    throw new Error("解密失败：口令错误或密文已损坏/被篡改");
  }

  const dec = new TextDecoder();
  return dec.decode(plainBuf);
}

function getIterations() {
  const n = Number($("iterations").value);
  if (!Number.isFinite(n) || n < 10000) throw new Error("PBKDF2 迭代次数需为 >= 10000 的数字");
  return Math.floor(n);
}

function normalizeCipherInput(s) {
  // 允许用户粘贴时带空格/换行：去掉所有空白
  return s.replace(/\s+/g, "");
}

async function onEncrypt() {
  const plain = $("plainIn").value;
  const pass = $("passEnc").value;
  if (!plain) throw new Error("请输入明文");
  if (!pass) throw new Error("请输入口令");
  const iterations = getIterations();

  const cipher = await encryptText(plain, pass, iterations);
  $("cipherOut").value = cipher;
  $("cipherIn").value = cipher; // 方便直接解密测试
  setStatus(`加密完成：输出长度 ${cipher.length}（只含 魑魅魍魉）`, "ok");
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
  const iterations = getIterations();
  const pass = "test-passphrase";
  const plain = `自检文本\n时间: ${new Date().toISOString()}\n随机: ${crypto.getRandomValues(new Uint32Array(1))[0]}`;

  const cipher = await encryptText(plain, pass, iterations);

  // 验证字符集
  assertCipherAlphabet(cipher);

  const back = await decryptText(cipher, pass, iterations);
  if (back !== plain) throw new Error("自检失败：解密结果与原文不一致");

  setStatus(`自检通过。密文长度=${cipher.length}，示例密文前 64 字：\n${cipher.slice(0, 64)}...`, "ok");
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

bind();
setStatus("准备就绪。你可以先点击“运行自检”。");