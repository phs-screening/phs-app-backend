const crypto = require('crypto');

async function hashPassword(password) {
    const encoder = new TextEncoder();
    const encodePassword = encoder.encode(password);
    const hashPassword = await crypto.subtle.digest('SHA-256', encodePassword);
    const hashArray = Array.from(new Uint8Array(hashPassword));
    const hashHex = hashArray.map((b) => b.toString(16).padStart(2, '0')).join('');
    return hashHex;
}

module.exports = { hashPassword };