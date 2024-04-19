const aes = require('crypto-js/aes');
const utf8 = require('crypto-js/enc-utf8');

flag = "bctf{345y-p4s5w0rd->w<}";
key = "p4wR0d"

const ciphertext = aes.encrypt(flag, key).toString();

const bytes = aes.decrypt(ciphertext, key);
const originalText = bytes.toString(utf8);

console.log(ciphertext);
console.log(originalText);
