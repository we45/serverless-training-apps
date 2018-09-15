const jwt = require("jsonwebtoken");
const hmac_password = "secret";
const ApiBuilder = require("claudia-api-builder");
const api = new ApiBuilder();
const fs = require("fs");
const AWS = require("aws-sdk");
const dynamo = new AWS.DynamoDB.DocumentClient();

module.exports = api;

api.get("/init", request => {
  let key = fs.readFileSync("private_key.pem", "utf8");
  console.log(key);
  let auth_token = jwt.sign({ user: "user", authenticated: false }, key, {
    algorithms: "RS256"
  });
  try {
    pub_key = fs.readFileSync("public_key.pem").toString("base64");
  } catch (err) {
    return new ApiBuilder.ApiResponse({ error: err }, 400);
  }

  return new ApiBuilder.ApiResponse(
    { token: auth_token, public_key: pub_key },
    { "X-Success-Request": true },
    200
  );
});

api.get("/confusion", request => {
  let auth_token = request.headers["Authorization"];
  let key = fs.readFileSync("public_key.pem", "utf8");
  try {
    let decoded = jwt.verify(auth_token, key, {
      algorithms: ["HS256", "RS256"]
    });
    return new ApiBuilder.ApiResponse(
      { success: "You are successfully authenticated", decoded: decoded },
      { "X-Success-Request": true },
      200
    );
  } catch (err) {
    return new ApiBuilder.ApiResponse({ error: err }, 400);
  }
});

api.get("/none", request => {
  let auth_token = request.headers["Authorization"];
  if (auth_token == null) {
    return new ApiBuilder.ApiResponse({ error: "No Auth token" }, {}, 403);
  }
  try {
    let decoded = jwt.decode(auth_token);
    return new ApiBuilder.ApiResponse({ decoded: decoded }, {}, 200);
  } catch (err) {
    return new ApiBuilder.ApiResponse({ error: err }, {}, 403);
  }
});

// api.post("/swtich_smith", request => {});

api.get("/whoami", request => {
  let auth_token = request.headers["Authorization"];
  if (auth_token == null) {
    return new ApiBuilder.ApiResponse({ error: "No Auth token" }, {}, 403);
  }
  try {
    let decoded = jwt.verify(
      auth_token,
      hmac_password,
      (algorithms = ["HS256"])
    );
    let userName = decoded["user_name"];
    console.log("User: ", userName);
    let params = {
      TableName: "dynamo-user",
      Key: {
        username: userName
      }
    };
    try {
      dynamo.get(params, function(err, data) {
        if (err) {
          console.log(err);
          return new ApiBuilder.ApiResponse({ error: err }, {}, 400);
        } else {
          console.log("Data: " + data);
          return new ApiBuilder.ApiResponse(({ data: data.Items }, {}, 200));
        }
      });
    } catch (err) {
      console.log(err);
    }
  } catch (err) {
    console.error(err);
    return new ApiBuilder.ApiResponse({ error: err }, {}, 400);
  }
});
