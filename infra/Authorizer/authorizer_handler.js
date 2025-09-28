// authorizer/authorizer_handler.js
const { createRemoteJWKSet, jwtVerify } = require("jose");

const tenantId  = process.env.TENANT_ID;                 // e.g., "aaaaaaaa-bbbb-cccc-...."
const issuer    = `https://login.microsoftonline.com/${tenantId}/v2.0`;
const jwks      = createRemoteJWKSet(new URL(`https://login.microsoftonline.com/${tenantId}/discovery/v2.0/keys`));
const audiences = (process.env.AUDIENCE || "").split(",").map(s => s.trim()).filter(Boolean);
const allowedClients = new Set((process.env.ALLOWED_CLIENT_IDS || "").split(",").filter(Boolean));

const allow = (arn, sub="aad-user") => ({
  principalId: sub,
  policyDocument: { Version:"2012-10-17", Statement:[{ Action:"execute-api:Invoke", Effect:"Allow", Resource: arn }] }
});
const deny = (arn) => ({
  principalId: "anonymous",
  policyDocument: { Version:"2012-10-17", Statement:[{ Action:"execute-api:Invoke", Effect:"Deny", Resource: arn }] }
});

exports.handler = async (event) => {
  try {
    const methodArn = event.methodArn;
    const token = (event.authorizationToken || "").replace(/^Bearer\s+/i, "");
    const { payload } = await jwtVerify(token, jwks, {
      issuer,
      audience: audiences.length > 1 ? audiences : audiences[0]
    });

    // Optional client/app whitelist
    const clientId = payload.appid || payload.azp; // confidential vs public clients
    if (allowedClients.size && !allowedClients.has(clientId)) return deny(methodArn);

    // Optional scope/role checks
    // if (!((payload.scp || "").split(" ").includes("Api.Read"))) return deny(methodArn);
    // if (!((payload.roles || []).includes("Api.Access"))) return deny(methodArn);

    return allow(methodArn, payload.sub || "aad-user");
  } catch (e) {
    console.log("JWT verify failed:", e?.message);
    return deny(event.methodArn);
  }
};
