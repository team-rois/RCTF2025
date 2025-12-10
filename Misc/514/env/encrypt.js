const crypto = require("crypto");

const keyBase64 = "";
const key = Buffer.from(keyBase64, "base64");


const iv = crypto.randomBytes(16);

// 要加密的字符串，base64后的token
const plaintext = "";


const cipher = crypto.createCipheriv("aes-256-cbc", key, iv);

let encrypted = cipher.update(plaintext, "utf8", "base64");
encrypted += cipher.final("base64");

const ivBase64 = iv.toString("base64");
const finalResult = encrypted + ivBase64;

console.log("✅ 加密结果（密文 + IV）:");
console.log(finalResult);

