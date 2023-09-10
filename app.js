const express = require('express');
const { JWK } = require('node-jose');
const {SignJWT, importJWK } = require('jose');
const {Issuer, generators } = require('openid-client');
const axios = require('axios');
const jwt = require('jsonwebtoken');
const uuid = require('uuid');
const dotenv  = require('dotenv');
const qs = require('querystring');
const jwksClient = require('jwks-rsa');

dotenv.config()

const app = express();
const port = 3000;

// Middleware to parse JSON request bodies
app.use(express.json());

app.use(express.urlencoded({ extended: true }));


// Create a route for the /authorize endpoint
app.get('/authorize', async (req, res) => {

    const { state, code_challenge } = req.query;
  // Generate code_verifier and code_challenge
  const code_verifier = generators.codeVerifier();
  console.log("code_verifier:", code_verifier);
  var eventual_code_challenge = code_challenge || generators.codeChallenge(code_verifier);

  // Store code_verifier in Vercel KV store
  const { kv } = require("@vercel/kv");
  const nonce = "12345";
  //await kv.set(`${code_verifier}:nonce`, nonce);
  //const nonce="12345";

   
    const auth0Issuer = await Issuer.discover(`https://${process.env.IDP_DOMAIN}`);

    //console.log('Discovered issuer %s %O', auth0Issuer.issuer, auth0Issuer.metadata);

    const client = new auth0Issuer.Client({
        client_id: process.env.IDP_CLIENT_ID,
        token_endpoint_auth_method: 'private_key_jwt',
        redirect_uris: [process.env.RP_REDIRECT_URI]

    });

    const url = client.authorizationUrl({
        scope: `openid`,
        nonce: nonce,
        response_type: "code",  
        code_challenge : eventual_code_challenge,
        code_challenge_method: 'S256',
        state: state

    });

    console.log(url);

  res.redirect(url);

});

// Create a route for the /token endpoint
app.post('/token', async (req, res) => {
    console.log(req.body);
  // Retrieve sessionId from the query parameters
  const { client_id, code, code_verifier, redirect_uri } = req.body;
  const auth0Issuer = await Issuer.discover(`https://${process.env.IDP_DOMAIN}`);
  const { kv } = require("@vercel/kv");
  //const nonce = await kv.get(`${code_verifier}:nonce`);
  const nonce = "12345";

  if (!client_id) {
    return res.status(400).send('Missing client_id');
  }

  if (process.env.IDP_CLIENT_ID === client_id) {
    try {
      const client_assertion = await generatePrivateKeyJWT(process.env);
      console.log(client_assertion);
      const options = {
        method: 'POST',
        url: auth0Issuer.token_endpoint,
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        data: qs.stringify({
          grant_type: 'authorization_code',
          client_id: process.env.IDP_CLIENT_ID,
          client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
          client_assertion,
          code,
          code_verifier,
          redirect_uri,
        }),
      };

      const response = await axios.request(options);
      //return res.status(200).send(response.data);
      console.log(response.data); 
      const { id_token } = response.data;

      const publicKeyIDP = await loadPublicKeyIDP(process.env);
    
       console.log(`nonce expected: ${nonce}`);

       const payload = await jwt.verify(id_token, publicKeyIDP, {
         issuer: `https://${process.env.IDP_DOMAIN}`,
         audience: process.env.IDP_CLIENT_ID,
       });
       console.log(payload)

       if (payload.nonce !== nonce) {
         return res.status(400).send('Nonce mismatch');
       } else {
         response.data.payload = payload;
         delete response.data.id_token;

         const key = await importJWK({
            kty: 'RSA',
            kid: 'QVBKtPRpC9s2cynBuEI7DMjXwtinIkdMQ-ZMUX2BKZg',
            e: 'AQAB',
            n: 'v7PiYOndb1xI0vFaXtQ7JW66lrRbeFrj0hFL3zYEMgscjBg5KfG2Etwak8W41AQz2eWAOhDtX42a8Tb7D51xuEpFHBoEqOoLB1NsU5J1v1uxFGUGT0g_vMTN7MUxBUzdghiI1a3TugZsTnQDXT4R0msQU1hCi7yXoPETB-AQb_0rifBYK3kgweGZ5hFOvkuy-fZihJGrNEoAt3_17dEi8uAoqiAAN4XPpz4MmYizBNjY0ykFKwo-SWdueHe6FnwJkeWYNzPNFjBvaiHP7SYyPsPcqV_c3S1jUHs9eeq51GiKRuozLRU2ktDP94_-foqwfY0aik2xKkYcN7K4_Ms4Nw',
            d: 'K3kRp0ShsLVO1ndhNQwP9acsrSxtadfCvkqp2A6Z2PdoG-UKYZas4Y4EgOpfxcTGNW20LHbWPcsRDg6X1Kyxs0c0cPD9iYi5w4mJkVIvXZvfhm56hdQukBJZWI5HVZpeyTfjIAHxd8gpG4l3kdeXlw4sf5oOTT4RbK_-ztRjJeHxUxqnzYgXGUWY0wM9rRsJzj3vL_zi4L3Xx47GFQGgbVAnBO-wg7wwDEKgiVEStP9PTbXUX8wuIX8t9DVRlMOcPjksDBULepKjeK3ljkORAEuIzjeSYYxwvSQmGIdotwcE9-KXL_nlGo4hMhEULGSzWHtCFeLvHvWQKP91brMl4Q',
            p: '4q2lNWWyT8k5jR8-qj5mKNDovveesjQClWgMAz8Kjdnddz0c1uLDG9D-eGRV3caNCaNcO5Npxq9UFHIzxVHWjZuz83gOcOZucr-S3zxnXj0r_IdWZbKUk_29NkFQ6Shih088pv3ddFeHK9jWAVToADg6kWrT9rrQZW0xkuKwdnk',
            q: '2IAJN4InDzvkMsyb_hlKmeHQiK5C4eQwiQROrdIF-w3oVTfX5r-lzWz9uxGVbeQshfZaEQxwK0zQxMvif_r0OF-Eu6JuF5pGp3uCmlrx5WfvkSSLm7u4xlbB9_t-nMhG_CF5RJ8X-hoo4he6d5LU4xlae9_UCh7nPivDoWWTOC8',
            dp: 'AcOUK4w1DQXl2sFJfY2qwdqOVR4cMArTklIS9duBu4TcglcJaGqvVgIUWN9_A5DN_Cs3RodpJVCr-NTCrmBqqQNzLQvcIOjKJz5yaCZSL5uOQhLTi0sOePBajpeHh6j2y1LEiBAlrwgXVzICyFPe0lGdsw__wkXF5WQqJJh7AxE',
            dq: 'Dy-j9d3OSZZE4n9RrdguUG7zhrLahCfSc7n2nuCthLesBVY-cbQduDQd9CI-ng-0Q81M8gcyUwc3WaaHg7yhptakY9j36fXrYNIcDiG0-Ad7WW370Pew9VCemHtunSa7O_JJJFQYhXWSSpGphbup7SgZHblMkU0roUPGnCqY0gc',
            qi: 'LtzwWittiDEMCqW1WOch4M9JnzcfLjCz2lBFTlGoiF6CxnOEQePKfmTZ7wK7LVi5nhSHh-PAkNrBhNMt4AEGUJ0DB92FMInAnknar_GCK67LC7bMo5JRLgVkGNXeDDpWyWEvgXitqYYzjwfLUD5MFYogiR5OXFLdTa_mfyEps_0'
          }, "RS256");
          
         const jwt = await new SignJWT(payload)
         .setProtectedHeader({ alg: "RS256", kid: "QVBKtPRpC9s2cynBuEI7DMjXwtinIkdMQ-ZMUX2BKZg", typ: "JWT" })
         .setIssuedAt()
         .setIssuer(`https://${process.env.IDP_DOMAIN}`)
         .setAudience(process.env.IDP_CLIENT_ID)
         .setExpirationTime('2m') // Expiration time
         .setJti(uuid.v4())
         .sign(key);
         console.log(jwt);
         response.data.id_token = jwt;
         return res.status(200).send(response.data);
       }
    } catch (error) {
        //console.error(error);
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
app.get('/.well-known/keys', async (req, res) => {
  // Create and return a JSON Web Key Set (JWKS)
  const jwks = {
    keys: [JWK.asKey({ kty: 'RSA', use: 'sig' })],
  };

  var publicKey =  process.env.RELYING_PARTY_PUBLIC_KEY.replace(/\n/g,"\r\n");
  var keystore = JWK.createKeyStore();
  //var key2 = await JWK.asKey(privateKey,"pem");     
   await keystore.add(publicKey, "pem");
  res.json(keystore.toJSON());
});


app.get('/jwks', async (req, res) => {
    // Create and return a JSON Web Key Set (JWKS)
    const jwks = {
      keys: [{
        kty: 'RSA',
        use: "sig",
        kid: 'QVBKtPRpC9s2cynBuEI7DMjXwtinIkdMQ-ZMUX2BKZg',
        e: 'AQAB',
        n: 'v7PiYOndb1xI0vFaXtQ7JW66lrRbeFrj0hFL3zYEMgscjBg5KfG2Etwak8W41AQz2eWAOhDtX42a8Tb7D51xuEpFHBoEqOoLB1NsU5J1v1uxFGUGT0g_vMTN7MUxBUzdghiI1a3TugZsTnQDXT4R0msQU1hCi7yXoPETB-AQb_0rifBYK3kgweGZ5hFOvkuy-fZihJGrNEoAt3_17dEi8uAoqiAAN4XPpz4MmYizBNjY0ykFKwo-SWdueHe6FnwJkeWYNzPNFjBvaiHP7SYyPsPcqV_c3S1jUHs9eeq51GiKRuozLRU2ktDP94_-foqwfY0aik2xKkYcN7K4_Ms4Nw'
      }],
    };
  
    res.json(jwks);
  });

// Start the Express server
app.listen(port, () => {
  console.log(`Server is listening at http://localhost:${port}`);
});


async function loadPrivateKey() {
    const baseUrl = getBaseUrl();
    try {
        const response = await axios.get(`${baseUrl}/.well-known/keys`);
        const { keys } = response.data;
        keys[0].d = process.env.RELYING_PARTY_PRIVATE_KEY;
        return await importJWK(keys[0], process.env.IDP_SIGNING_ALG);
    } catch (e) {
      return e;
    }
  }
  
  async function loadPublicKey() {

    const baseUrl = getBaseUrl();
    try {
      const response = await axios.get(`${baseUrl}/.well-known/keys`);
      console.log(response.data);
      const publicKey = await importJWK(response.data.keys[0], process.env.IDP_SIGNING_ALG);
      console.log(publicKey);
      return publicKey;
    } catch (e) {
      return e;
    }
  }

  async function loadPublicKeyIDP() {
    try {

        const client = jwksClient({
        jwksUri: `https://${process.env.IDP_DOMAIN}/jwks`,
        requestHeaders: {}, // Optional
        timeout: 30000 // Defaults to 30s
        });
        const kid = process.env.IDP_SIGNING_KEY_KID;
        const key = await client.getSigningKey(kid);
        console.log(key);
        const signingKey = key.publicKey || key.rsaPublicKey;
    return signingKey;
    } catch (e) {
      return e;
    }
  }
  
  async function generatePrivateKeyJWT() {
    try {
      const key = await loadPrivateKey();
      console.log(key);
      const jwt = await new SignJWT({})
        .setProtectedHeader({ alg: process.env.IDP_SIGNING_ALG, kid: process.env.RELYING_PARTY_KID, typ: "JWT" })
        .setIssuedAt()
        .setIssuer(process.env.IDP_CLIENT_ID)
        .setSubject(process.env.IDP_CLIENT_ID)
        .setAudience([`https://${process.env.IDP_DOMAIN}/`, `https://${process.env.IDP_DOMAIN}/token`])
        .setExpirationTime('2m') // Expiration time
        .setJti(uuid.v4())
        .sign(key);
        console.log(jwt);

      return jwt;
    } catch (error) {
      console.log(error);
      return error;
    }
  }

  const getBaseUrl = () => {
    if (process.env.NODE_ENV === "development") {
      return `${process.env.DEV_RP_URL}`
    }
    
    return `${process.env.NEXT_PUBLIC_VERCEL_URL}`;
  };