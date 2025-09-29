import { createRemoteJWKSet, jwtVerify } from "jose";

const TENANT_ID = process.env.TENANT_ID; // d1df0ad0-...
const AUD = process.env.EXPECTED_AUD;    // e.g. "api://10f7...f58e"
const ISS_V2 = `https://login.microsoftonline.com/${TENANT_ID}/v2.0`;
const OIDC = `https://login.microsoftonline.com/${TENANT_ID}/v2.0/.well-known/openid-configuration`;

let jwks;
async function getJwks() {
  if (!jwks) {
    // You can hardcode the jwks_uri if you want to avoid fetching OIDC doc.
    // For brevity we jump straight to the documented JWKS endpoint pattern:
    const jwksUri = `https://login.microsoftonline.com/${TENANT_ID}/discovery/v2.0/keys`;
    jwks = createRemoteJWKSet(new URL(jwksUri));
  }
  return jwks;
}

export const handler = async (event) => {
  try {
    let raw = event.authorizationToken || event.headers?.Authorization || "";
    raw = Array.isArray(raw) ? raw[0] : raw;
    let token = String(raw).replace(/^Bearer\s+/i, "").trim();
    token = token.replace(/[\r\n]/g, "").replace(/^"+|"+$/g, "");

    if (token.split(".").length !== 3) {
      throw new Error("Not a compact JWS (expect 3 segments)");
    }

    const jwks = await getJwks();
    const { payload, protectedHeader } = await jwtVerify(token, jwks, {
      issuer: ISS_V2,
      audience: AUD,           // exact match to your API App ID URI
      algorithms: ["RS256"],
    });

    // (Optional) role/scope checks here

    return generatePolicy("Allow", event.methodArn);
  } catch (err) {
    console.error("Auth error:", err.message);
    return generatePolicy("Deny", event.methodArn);
  }
};

function generatePolicy(effect, resource) {
  return {
    principalId: "user",
    policyDocument: {
      Version: "2012-10-17",
      Statement: [{ Action: "execute-api:Invoke", Effect: effect, Resource: resource }],
    },
    context: { reason: effect },
  };
}
