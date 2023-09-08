const { generators } = require('openid-client');
const { createResponse } = require('@vercel/node');

module.exports = async (req, res) => {
  const { query } = req;
  const { code, state } = query;

  // Retrieve code_verifier from Vercel KV store
  const { KV } = require('@vercel/node');
  const codeVerifierStore = new KV('code-verifiers');
  const code_verifier = await codeVerifierStore.get(`${state}:code_verifier`);
  const nonce = await codeVerifierStore.get(`${state}:nonce`);

  if (!code_verifier) {
    return createResponse(res).status(400).send('Invalid code_verifier');
  }

  if (!nonce) {
    return createResponse(res).status(400).send('Invalid nonce');
  }

  var keyJSON2 = {
    "kty": "EC",
    "use": "sig",
    "crv": "P-256",
    "kid": "sig-2021-08-30T04:38:19Z",
    "x": "pQ6PL6JX14NpKka8j261yHMYsCQ6t3YMlDLpwIIxYcI",
    "y": "NHYjUfuLspMW_-5PaulnvkRd34vYeVogpl-WFv8tRkc",
    "alg": "ES256",
    "d" : "2FwqOVMxvumPcB4-wI0ZkTHnUYQcoj4TGwf3Ulq7E6s"
};


var key = await JWK.asKey(keyJSON2)
var keystore = JWK.createKeyStore();
await keystore.add(key);

const auth0Issuer = await Issuer.discover(`https://${process.env.DOMAIN}`);

//console.log('Discovered issuer %s %O', auth0Issuer.issuer, auth0Issuer.metadata);


const client = new auth0Issuer.Client({
    client_id: process.env.PKJWT_CLIENT_ID,
    token_endpoint_auth_method: 'private_key_jwt',
    redirect_uris: [process.env.PKJWT_REDIRECT_URI]

},keystore.toJSON(true));

  // Use code_verifier and code_challenge as needed


  const tokenSet = await client.callback(process.env.PKJWT_REDIRECT_URI, params, {"nonce" : nonce,"code_verifier": code_verifier });

  // For simplicity, respond with a success message
  const response = createResponse(res);
  response.send('Token request successful');
};
