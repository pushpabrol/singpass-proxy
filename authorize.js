
import pkg from 'node-jose';
const { JWK } = pkg;
const {Issuer, generators } = require('openid-client');
const { createResponse } = require('@vercel/node');

module.exports = async (req, res) => {
  // Generate code_verifier and code_challenge
  const code_verifier = generators.codeVerifier();
  const code_challenge = generators.codeChallenge(code_verifier);

  // Store code_verifier in Vercel KV store
  const { KV } = require('@vercel/node');
  const codeVerifierStore = new KV('code-verifiers');
  const nonce = generators.nonce();
  const state = generators.state();
  await codeVerifierStore.set(`${state}:code_verifier`, code_verifier);
  await codeVerifierStore.set(`${state}:nonce`, nonce);

    var keyJSON = {
        "kty": "EC",
        "use": "sig",
        "crv": "P-256",
        "kid": "sig-2021-08-30T04:38:19Z",
        "x": "pQ6PL6JX14NpKka8j261yHMYsCQ6t3YMlDLpwIIxYcI",
        "y": "NHYjUfuLspMW_-5PaulnvkRd34vYeVogpl-WFv8tRkc",
        "alg": "ES256",
        "d" : "2FwqOVMxvumPcB4-wI0ZkTHnUYQcoj4TGwf3Ulq7E6s"
    };
    
    
    var key = await JWK.asKey(keyJSON)
    var keystore = JWK.createKeyStore();
    await keystore.add(key);

    const auth0Issuer = await Issuer.discover(`https://${process.env.DOMAIN}`);

    //console.log('Discovered issuer %s %O', auth0Issuer.issuer, auth0Issuer.metadata);

    const client = new auth0Issuer.Client({
        client_id: process.env.SINGPASS_CLIENT_ID,
        token_endpoint_auth_method: 'private_key_jwt',
        redirect_uris: [process.env.RP_REDIRECT_URI]

    },keystore.toJSON(true));

    const url = client.authorizationUrl({
        scope: `openid`,
        nonce: nonce,
        state:state,
        response_type: "code",  
        code_challenge,
        code_challenge_method: 'S256',

    });

    console.log(url);


  const response = createResponse(res);
  response.redirect(url);
};
