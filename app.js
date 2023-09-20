// Import required Node.js modules and libraries
const express = require('express');
const { JWK, JWE } = require('node-jose');
const { SignJWT, importJWK, importPKCS8, jwtVerify, createRemoteJWKSet } = require('jose'); // JSON Object Signing and Encryption (JOSE) library
const axios = require('axios');
const uuid = require('uuid');
const dotenv = require('dotenv');
const qs = require('querystring');

const relyingPartyJWKS = require('./spkis/relyingPartyJWKS.json');
const intermediaryJWKS = require('./spkis/intermediaryJWKS.json');

const decode = (input) => Buffer.from(input, 'base64');


dotenv.config(); // Load environment variables from the .env file

const app = express(); // Create an Express application
const port = 3000; // Define the port for the server to listen on

// Middleware to parse JSON request bodies
app.use(express.json());

// Middleware to parse URL-encoded request bodies
app.use(express.urlencoded({ extended: true }));

// Create a route for the /token endpoint
app.post('/token', async (req, res) => {
  const context = req.webtaskContext || process.env;
  console.log(req.body);

  // Retrieve parameters from the request body
  const { client_id, code, code_verifier, redirect_uri } = req.body;

  // Check if the client_id is missing
  if (!client_id) {
    return res.status(400).send('Missing client_id');
  }

  // Check if the provided client_id matches the expected one
  if (context.IDP_CLIENT_ID === client_id) {
    try {
      // Generate a client_assertion (JWT) for client authentication
      const client_assertion = await generatePrivateKeyJWTForClientAssertion(context);
      console.log(client_assertion);

      // Prepare the request to exchange the authorization code for tokens
      const options = {
        method: 'POST',
        url: `https://${context.IDP_DOMAIN}/token`,
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        data: qs.stringify({
          grant_type: 'authorization_code',
          client_id: context.IDP_CLIENT_ID,
          client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
          client_assertion,
          code,
          code_verifier,
          redirect_uri,
        }),
      };

      // Send the token request to the authorization server
      const response = await axios.request(options);
      console.log(response.data);

      // Extract the id_token from the response
      const { id_token } = response.data;

      // Extract the id_token from the response
      const decryted_id_token = await decryptJWE(id_token, context);

      const publicKeyIDP = createRemoteJWKSet(new URL(`https://${context.IDP_DOMAIN}${context.IDP_JWKS_PATH}`))

      // Verify the id_token with the public key
      const { payload, protectedHeader } = await jwtVerify(decryted_id_token, publicKeyIDP, {
        issuer: `https://${context.IDP_DOMAIN}`,
        audience: context.IDP_CLIENT_ID,
      });

      console.log(payload);
      console.log(protectedHeader);
      // Remove the nonce from the payload and replace the id_token with a new RS256 token
      if (payload.nonce) delete payload.nonce;
      response.data.payload = payload;
      delete response.data.id_token;

      // Generate an RS256 token from the payload for auth0
      const jwt = await generateRS256Token(payload, context);
      response.data.id_token = jwt;

      // Send the response with the updated id_token
      return res.status(200).send(response.data);

    } catch (error) {
      if (error.response) {
        // Handle errors with HTTP responses
        return res.status(error.response.status).send(error.response.data);
      } else {
        console.error('Error:', error.message);
        return res.status(500).send(error.message);
      }
    }
  } else {
    // Return an error response for invalid client_id
    return res.status(401).send('Invalid request, client_id is incorrect!');
  }
});

// Create a route for /.well-known/keys
// Used by the relying party of IDP to provide an ES256 public key for client authentication
app.get('/.well-known/keys', async (req, res) => {
  res.json(relyingPartyJWKS);
});

// This route returns the RS256 public key, used as the JWKS URL by auth0 to verify RS256 tokens
app.get('/jwks', async (req, res) => {
  res.json(intermediaryJWKS);
});

// Start the Express server and listen on the specified port
app.listen(port, () => {
  console.log(`Server is listening at http://localhost:${port}`);
});

// Function to load the private key for client_assertion - ES256
async function loadPrivateKeyForClientAssertion(context) {
  try {

    var jsonData = relyingPartyJWKS.keys.find(spki => spki.use === "sig");
    jsonData.d = context.RELYING_PARTY_PRIVATE_KEY_SIGNING;
    return await importJWK(jsonData, context.RELYING_PARTY_CLIENT_ASSERTION_SIGNING_ALG);
  } catch (e) {
    return e;
  }
}

// Function to load the RS256 private key
async function loadRS256PrivateKey(context) {
  try {
    var privateKey = context.INTERMEDIARY_PRIVATE_KEY.replace(/\n/g, "\r\n");
    var key = await importPKCS8(privateKey, context.INTERMEDIARY_SIGNING_ALG);
    return key;
  } catch (e) {
    console.log(e);
    return e;
  }
}



// Function to generate a client_assertion (JWT) for client authentication
async function generatePrivateKeyJWTForClientAssertion(context) {
  try {
    const key = await loadPrivateKeyForClientAssertion(context);
    console.log(key);
    const jwt = await new SignJWT({})
      .setProtectedHeader({ alg: context.RELYING_PARTY_CLIENT_ASSERTION_SIGNING_ALG, kid: context.RELYING_PARTY_KID, typ: "JWT" })
      .setIssuedAt()
      .setIssuer(context.IDP_CLIENT_ID)
      .setSubject(context.IDP_CLIENT_ID)
      .setAudience([`https://${context.IDP_DOMAIN}/`, `https://${context.IDP_DOMAIN}/token`])
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

// Function to generate an RS256 token by the intermediary
async function generateRS256Token(payload, context) {
  if (payload.nonce) delete payload.nonce;
  try {
    const key = await loadRS256PrivateKey(context);
    console.log(key);
    const jwt = await new SignJWT(payload)
      .setProtectedHeader({ alg: context.INTERMEDIARY_SIGNING_ALG, kid: context.INTERMEDIARY_KEY_KID, typ: "JWT" })
      .setIssuedAt()
      .setIssuer(`https://${context.IDP_DOMAIN}`)
      .setAudience(context.IDP_CLIENT_ID)
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

async function decryptJWE(jwe, context) {

  var jsonData = relyingPartyJWKS.keys.find(spki => spki.use === "enc" && spki.alg === context.RELYING_PARTY_PRIVATE_KEY_ENC_ALG);
  
  if (jsonData) {
    jsonData.d = context.RELYING_PARTY_PRIVATE_KEY_ENC;
    try {
      if(!checkTokenEncryptionAlgEnc(jwe,context)) throw new Error("Token from IDP - Encryption and/or encoding mismatch!");
      const decryptor = JWE.createDecrypt(await JWK.asKey(jsonData, "json"));
      const decryptedData = await decryptor.decrypt(jwe);
      const idToken = decryptedData.plaintext.toString('utf8');
      console.log(idToken);
      return idToken;
    }

    catch (e) {
      console.log(e);
      throw e;
    }
  } else {
    console.log("Either not encrypted or the right key is not available!, returning token as is!")
    return jwe;
  }

}


function checkTokenEncryptionAlgEnc(jwe, context) {
  const expectedAlg = context.RELYING_PARTY_PRIVATE_KEY_ENC_ALG;
  const expectedEnc = context.RELYING_PARTY_PRIVATE_KEY_ENC_ENC;
  const header = JSON.parse(decode(jwe.split('.')[0]));
  var asExtpected = true;

  if (header.alg !== expectedAlg) {
    console.log(`unexpected JWE alg received, expected ${expectedAlg}, got: ${header.alg}`)
    asExtpected = false;
  }

  if (header.enc !== expectedEnc) {
    console.log(`unexpected JWE enc received, expected ${expectedEnc}, got: ${header.enc}`)
    asExtpected = false;
  }
  return asExtpected;

}
