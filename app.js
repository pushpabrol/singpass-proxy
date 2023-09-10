const express = require('express');
const { JWK } = require('node-jose');
const {SignJWT, importJWK, importPKCS8,  } = require('jose');
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

  const nonce = "12345";
   
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

    //console.log(url);

  res.redirect(url);

});

// Create a route for the /token endpoint
app.post('/token', async (req, res) => {
    console.log(req.body);
  // Retrieve sessionId from the query parameters
  const { client_id, code, code_verifier, redirect_uri } = req.body;
  const auth0Issuer = await Issuer.discover(`https://${process.env.IDP_DOMAIN}`);
  const nonce = "12345";

  if (!client_id) {
    return res.status(400).send('Missing client_id');
  }

  if (process.env.IDP_CLIENT_ID === client_id) {
    try {
      const client_assertion = await generatePrivateKeyJWTForClientAssertion(process.env);
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
         delete payload.nonce;
         response.data.payload = payload;
         delete response.data.id_token;
        //genreate R2256 token from payload for auth0
        const jwt = await generateRS256Token(payload);
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
    return res.status(401).send('Invalid request, client_d is incorrect!');
  }

});

// Create a route for /.well-known/keys
// used by the relying part of IDP to provide an ES256 public key for client authentication used by the IDP for verifying client assertion
app.get('/.well-known/keys', async (req, res) => {
  // Create and return a JSON Web Key Set (JWKS)
  var publicKey =  process.env.RELYING_PARTY_PUBLIC_KEY.replace(/\n/g,"\r\n");
  var keystore = JWK.createKeyStore();
  //var key2 = await JWK.asKey(privateKey,"pem");     
   await keystore.add(publicKey, "pem");
  res.json(keystore.toJSON());
});

// this route returns the RS256 public key - this url becomes the jwks url used by auth0 to verify the RS256 token created
app.get('/jwks', async (req, res) => {
    // Create and return a JSON Web Key Set (JWKS)

    var publicKey =  process.env.INTERMEDIARY_PUBLIC_KEY.replace(/\n/g,"\r\n");
    var keystore = JWK.createKeyStore();
    //var key2 = await JWK.asKey(privateKey,"pem");     
     await keystore.add(publicKey, "pem");
    res.json(keystore.toJSON());
  });

// Start the Express server
app.listen(port, () => {
  console.log(`Server is listening at http://localhost:${port}`);
});


async function loadPrivateKeyForClientAssertion() {
    try {
        var publicKey =  process.env.RELYING_PARTY_PUBLIC_KEY.replace(/\n/g,"\r\n");
        const key = await JWK.asKey(publicKey,"pem");
        var jsonData = key.toJSON();
        jsonData.d = process.env.RELYING_PARTY_PRIVATE_KEY;
        return await importJWK(jsonData, process.env.RELYING_PARTY_CLIENT_ASSERTION_SIGNING_ALG);
    } catch (e) {
      return e;
    }
  }

  async function loadRS256PrivateKey() {
    try {
        var privateKey =  process.env.INTERMEDIARY_PRIVATE_KEY.replace(/\n/g,"\r\n");
        //console.log(privateKey);
        var key = await importPKCS8(privateKey,process.env.INTERMEDIARY_SIGNING_ALG);
        return key;
    } catch (e) {
        console.log(e);
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
        console.log(key.asKey);
        const signingKey = key.publicKey || key.rsaPublicKey;
    return signingKey;
    } catch (e) {
      return e;
    }
  }
  
  async function generatePrivateKeyJWTForClientAssertion() {
    try {
      const key = await loadPrivateKeyForClientAssertion();
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

  async function generateRS256Token(payload){
    if(payload.nonce) delete payload.nonce;
    try {
        const key = await loadRS256PrivateKey();
        console.log(key);
        const jwt = await new SignJWT(payload)
          .setProtectedHeader({ alg: process.env.INTERMEDIARY_SIGNING_ALG, kid: process.env.INTERMEDIARY_KEY_KID, typ: "JWT" })
          .setIssuedAt()
          .setIssuer(`https://${process.env.IDP_DOMAIN}`)
          .setAudience(process.env.IDP_CLIENT_ID)
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
