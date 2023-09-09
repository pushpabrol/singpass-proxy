const express = require('express');
const { JWK, SignJWT, parseJwk } = require('node-jose');
const {Issuer, generators } = require('openid-client');
const axios = require('axios');
const jwt = require('jsonwebtoken');
const uuid = require('uuid');
const dotenv  = require('dotenv');
dotenv.config()

const app = express();
const port = 3000;

// Middleware to parse JSON request bodies
app.use(express.json());


// Create a route for the /authorize endpoint
app.get('/authorize', async (req, res) => {
  // Generate code_verifier and code_challenge
  const code_verifier = generators.codeVerifier();
  const code_challenge = generators.codeChallenge(code_verifier);

  // Store code_verifier in Vercel KV store
  const { kv } = require("@vercel/kv");
  const nonce = generators.nonce();
  await kv.set(`${code_verifier}:nonce`, nonce);

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

  res.redirect(url);

});

// Create a route for the /token endpoint
app.post('/token', async (req, res) => {
  // Retrieve sessionId from the query parameters
  const { client_id, code, code_verifier, redirect_uri } = req.body;


  const nonce = await kv.get(`${code_verifier}:nonce`);

  if (!client_id) {
    return res.status(400).send('Missing client_id / client_secret');
  }

  if (process.env.SINGPASS_CLIENT_ID === client_id) {
    try {
      const client_assertion = await generatePrivateKeyJWT(process.env);

      const options = {
        method: 'POST',
        url: `https://${process.env.DOMAIN}/token`,
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        data: qs.stringify({
          grant_type: 'authorization_code',
          client_id: process.env.SINGPASS_CLIENT_ID,
          client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
          client_assertion,
          code,
          code_verifier,
          redirect_uri,
        }),
      };

      const response = await axios.request(options);
      //return res.status(200).send(response.data);
       const { id_token } = response.data;
      const publicKey = await loadPublicKey(process.env);

    
       console.log(`nonce expected: ${nonce}`);

       const { payload, protectedHeader } = await jwt.verify(id_token, publicKey, {
         issuer: `https://${process.env.DOMAIN}/`,
         audience: process.env.SINGPASS_CLIENT_ID,
       });

       if (payload.nonce !== nonce) {
         return res.status(400).send('Nonce mismatch');
       } else {
         response.data.payload = payload;
         return res.status(200).send(response.data);
       }
    } catch (error) {
      if (error.response) {
        return res.status(error.response.status).send(error.response.data);
      } else {
        console.error('Error:', error.message);
        return res.status(500).send(error.message);
      }
    }
  } else {
    return res.status(401).send('Invalid request');
  }

});

// Create a route for /.well-known/jwks.json
app.get('/.well-known/jwks.json', (req, res) => {
  // Create and return a JSON Web Key Set (JWKS)
  const jwks = {
    keys: [JWK.asKey({ kty: 'RSA', use: 'sig' })],
  };

  //res.json(jwks);
  res.json({
    "keys": [
    {
    "kty": "EC",
    "use": "sig",
    "crv": "P-256",
    "kid": "sig-2021-08-30T04:38:19Z",
    "x": "pQ6PL6JX14NpKka8j261yHMYsCQ6t3YMlDLpwIIxYcI",
    "y": "NHYjUfuLspMW_-5PaulnvkRd34vYeVogpl-WFv8tRkc",
    "alg": "ES256"
    }
    ]
    });
});

// Start the Express server
app.listen(port, () => {
  console.log(`Server is listening at http://localhost:${port}`);
});


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
        .setAudience(`https://${process.env.DOMAIN}/`)
        .setExpirationTime('2m') // Expiration time
        .setJti(uuid.v4())
        .sign(key);
      return jwt;
    } catch (error) {
      return error;
    }
  }