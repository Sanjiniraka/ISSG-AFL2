const io = require("socket.io-client");
const readline = require("readline");
const crypto = require("crypto");

const socket = io("http://localhost:3000");

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
  prompt: "> ",
});

// this client has its OWN key pair, not the victim's
const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
  modulusLength: 2048,
  publicKeyEncoding: { type: "spki", format: "pem" },
  privateKeyEncoding: { type: "pkcs8", format: "pem" },
});

let registeredUsername = "";
let username = "";
let targetUsername = "";
let asked = false;
const users = new Map();

const sha256 = (text) =>
  crypto.createHash("sha256").update(text).digest("hex");

function sendMessage(text) {
  let body = text;
  const data = { username };

  if (targetUsername) {
    body = crypto
      .publicEncrypt(
        { key: users.get(targetUsername), oaepHash: "sha256" },
        Buffer.from(text)
      )
      .toString("base64");
    data.to = targetUsername;
  }

  data.message = body;
  data.hash = sha256(body);
  data.signature = crypto
    .sign("sha256", Buffer.from(body), privateKey)
    .toString("base64");

  socket.emit("message", data);
}

function askUsername() {
  rl.question("Enter your username: ", (input) => {
    username = input;
    registeredUsername = input;
    console.log(`Welcome, ${username} to the chat`);

    socket.emit("registerPublicKey", { username, publicKey });
    rl.prompt();

    rl.on("line", (message) => {
      let match;
      if (message.trim()) {
        if ((match = message.match(/^!impersonate (\w+)$/))) {
          username = match[1];
          console.log(`Now impersonating as ${username}`);
        } else if (message.match(/^!stop$/)) {
          username = registeredUsername;
          console.log(`Now you are ${username}`);
        } else if ((match = message.match(/^!secret (\w+)$/))) {
          if (users.has(match[1])) {
            targetUsername = match[1];
            console.log(`Now secretly chatting with ${targetUsername}`);
          } else {
            console.log(`User ${match[1]} not found`);
          }
        } else if (message.match(/^!exit$/)) {
          console.log(`No more secretly chatting with ${targetUsername}`);
          targetUsername = "";
        } else {
          sendMessage(message);
        }
      }
      rl.prompt();
    });
  });
}

socket.on("connect", () => {
  console.log("Connected to the server");
});

socket.on("init", (keys) => {
  keys.forEach(([user, key]) => users.set(user, key));
  console.log(`There are currently ${users.size} users in the chat`);
  if (!asked) {
    asked = true;
    askUsername();
  }
});

socket.on("newUser", (data) => {
  users.set(data.username, data.publicKey);
  if (data.username === registeredUsername) return;
  console.log(`\n${data.username} joined the chat`);
  if (username) rl.prompt();
});

socket.on("message", (data) => {
  const { username: sender, message, hash, signature, to } = data;
  if (sender === username) return;

  const tampered = sha256(message) !== hash;

  let verified = false;
  try {
    verified = crypto.verify(
      "sha256",
      Buffer.from(message),
      users.get(sender),
      Buffer.from(signature, "base64")
    );
  } catch (e) {}

  let text = message;
  if (to === username) {
    try {
      text = crypto
        .privateDecrypt(
          { key: privateKey, oaepHash: "sha256" },
          Buffer.from(message, "base64")
        )
        .toString("utf8");
    } catch (e) {
      text = "[could not decrypt]";
    }
  }

  console.log(`\n${sender}: ${text}`);
  if (tampered) {
    console.log("⚠️  the message may have been changed during transmission");
  } else if (!verified) {
    console.log("⚠️  this user is fake");
  }
  rl.prompt();
});

socket.on("disconnect", () => {
  console.log("Server disconnected, Exiting...");
  rl.close();
  process.exit(0);
});

rl.on("SIGINT", () => {
  console.log("\nExiting...");
  socket.disconnect();
  rl.close();
  process.exit(0);
});