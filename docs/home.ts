import { generateKeyAndHash } from "@fungi.computer/ear-tag";

const { key, digest } = await generateKeyAndHash({ prefix: "invite" });
console.log(key.startsWith("invite_")); // true
console.log(digest.length); // 64: a SHA-256 digest as lowercase hex
