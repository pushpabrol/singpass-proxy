const axios = require('axios');
const { SignJWT, parseJwk } = require('node-jose');
const uuid = require('uuid');

async function loadPrivateKey() {
  try {
    //const response = await axios.get(config.RELYING_PARTY_JWKS_ENDPOINT);
    //const { keys } = response.data;
    const keys = [
        {
        "kty": "EC",
        "use": "sig",
        "crv": "P-256",
        "kid": "sig-2021-08-30T04:38:19Z",
        "x": "pQ6PL6JX14NpKka8j261yHMYsCQ6t3YMlDLpwIIxYcI",
        "y": "NHYjUfuLspMW_-5PaulnvkRd34vYeVogpl-WFv8tRkc",
        "alg": "ES256"
        }
        ];
    keys[0].d = process.env.RELYING_PARTY_PRIVATE_KEY;
    return await parseJwk(keys[0], process.env.SINGPASS_SIGNING_ALG);
  } catch (e) {
    return e;
  }
}

async function loadPublicKey() {
  try {
    const response = await axios.get(`https://${process.env.DOMAIN}/.well-known/keys`);
    const publicKey = await parseJwk(response.data.keys[0], process.env.SINGPASS_SIGNING_ALG);
    return publicKey;
  } catch (e) {
    return e;
  }
}

async function generatePrivateKeyJWT() {
  try {
    const key = await loadPrivateKey();
    const jwt = await new SignJWT({})
      .setProtectedHeader({ alg: process.env.SINGPASS_SIGNING_ALG, kid: process.env.RELYING_PARTY_KID, typ: "JWT" })
      .setIssuedAt()
      .setIssuer(process.env.SINGPASS_CLIENT_ID)
      .setSubject(process.env.SINGPASS_CLIENT_ID)
      .setAudience(process.env.SINGPASS_ENVIRONMENT)
      .setExpirationTime('2m') // Expiration time
      .setJti(uuid.v4())
      .sign(key);
    return jwt;
  } catch (error) {
    return error;
  }
}

module.exports = { loadPrivateKey, loadPublicKey, generatePrivateKeyJWT };
