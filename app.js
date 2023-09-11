// Import required Node.js modules and libraries
const express = require('express');
const { JWK } = require('node-jose');
const { SignJWT, importJWK, importPKCS8 } = require('jose'); // JSON Object Signing and Encryption (JOSE) library
const { Issuer, generators } = require('openid-client');
const axios = require('axios'); // HTTP client for making requests
const jwt = require('jsonwebtoken'); // JSON Web Token (JWT) library
const uuid = require('uuid'); // Universally Unique Identifier (UUID) generator
const dotenv = require('dotenv'); // Load environment variables from a .env file
const qs = require('querystring'); // Query string parsing and formatting
const jwksClient = require('jwks-rsa'); // JSON Web Key Set (JWKS) client for retrieving public keys

dotenv.config(); // Load environment variables from the .env file

const app = express(); // Create an Express application
const port = 3000; // Define the port for the server to listen on

// Middleware to parse JSON request bodies
app.use(express.json());

// Middleware to parse URL-encoded request bodies
app.use(express.urlencoded({ extended: true }));

// Create a route for the /authorize endpoint
app.get('/authorize', async (req, res) => {
  // Extract query parameters from the request
  const { state, code_challenge } = req.query;

  // Generate a code_verifier and code_challenge
  const code_verifier = generators.codeVerifier();
  console.log("code_verifier:", code_verifier);
  var eventual_code_challenge = code_challenge || generators.codeChallenge(code_verifier);

  const nonce = "12345";

  // Discover the OpenID Connect issuer and create a client
  const auth0Issuer = await Issuer.discover(`https://${process.env.IDP_DOMAIN}`);
  const client = new auth0Issuer.Client({
    client_id: process.env.IDP_CLIENT_ID,
    token_endpoint_auth_method: 'private_key_jwt',
    redirect_uris: [process.env.RP_REDIRECT_URI]
  });

  // Generate the authorization URL with required parameters
  const url = client.authorizationUrl({
    scope: `openid`,
    nonce: nonce,
    response_type: "code",
    code_challenge: eventual_code_challenge,
    code_challenge_method: 'S256',
    state: state
  });

  // Redirect the user to the authorization URL
  res.redirect(url);
});

// Create a route for the /token endpoint
app.post('/token', async (req, res) => {
  console.log(req.body);

  // Retrieve parameters from the request body
  const { client_id, code, code_verifier, redirect_uri } = req.body;
  const auth0Issuer = await Issuer.discover(`https://${process.env.IDP_DOMAIN}`);
  const nonce = "12345";

  // Check if the client_id is missing
  if (!client_id) {
    return res.status(400).send('Missing client_id');
  }

  // Check if the provided client_id matches the expected one
  if (process.env.IDP_CLIENT_ID === client_id) {
    try {
      // Generate a client_assertion (JWT) for client authentication
      const client_assertion = await generatePrivateKeyJWTForClientAssertion(process.env);
      console.log(client_assertion);

      // Prepare the request to exchange the authorization code for tokens
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

      // Send the token exchange request to the authorization server
      const response = await axios.request(options);
      console.log(response.data);

      // Extract the id_token from the response
      const { id_token } = response.data;

      const decryted_id_token = await decryptJWE(id_token);

      // Load the public key of the IDP for verification
      const publicKeyIDP = await loadPublicKeyIDP(process.env);

      console.log(`nonce expected: ${nonce}`);

      // Verify the id_token with the public key
      const payload = await jwt.verify(decryted_id_token, publicKeyIDP, {
        issuer: `https://${process.env.IDP_DOMAIN}`,
        audience: process.env.IDP_CLIENT_ID,
      });
      console.log(payload);

      // Check if the nonce in the payload matches the expected nonce
      if (payload.nonce !== nonce) {
        return res.status(400).send('Nonce mismatch');
      } else {
        // Remove the nonce from the payload and replace the id_token with a new RS256 token
        delete payload.nonce;
        response.data.payload = payload;
        delete response.data.id_token;

        // Generate an RS256 token from the payload for auth0
        const jwt = await generateRS256Token(payload);
        response.data.id_token = jwt;

        // Send the response with the updated id_token
        return res.status(200).send(response.data);
      }
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
  // Create and return a JSON Web Key Set (JWKS) containing the public key
  var publicKey = process.env.RELYING_PARTY_PUBLIC_KEY.replace(/\n/g, "\r\n");
  var publicKeyEnc = process.env.RELYING_PARTY_PUBLIC_KEY_ENC.replace(/\n/g, "\r\n");
  var keystore = JWK.createKeyStore();
  await keystore.add(publicKey, "pem", {"use" : "sig"});
  await keystore.add(publicKeyEnc, "pem", {"use" : "enc","alg": "ECDH-ES+A128KW"});
  res.json(keystore.toJSON());
});

// This route returns the RS256 public key, used as the JWKS URL by auth0 to verify RS256 tokens
app.get('/jwks', async (req, res) => {
  // Create and return a JSON Web Key Set (JWKS) containing the RS256 public key
  var publicKey = process.env.INTERMEDIARY_PUBLIC_KEY.replace(/\n/g, "\r\n");
  var keystore = JWK.createKeyStore();
  await keystore.add(publicKey, "pem");
  res.json(keystore.toJSON());
});

// Start the Express server and listen on the specified port
app.listen(port, () => {
  console.log(`Server is listening at http://localhost:${port}`);
});

// Function to load the private key for client_assertion
async function loadPrivateKeyForClientAssertion() {
  try {
    var publicKey = process.env.RELYING_PARTY_PUBLIC_KEY.replace(/\n/g, "\r\n");
    const key = await JWK.asKey(publicKey, "pem");
    var jsonData = key.toJSON();
    jsonData.d = process.env.RELYING_PARTY_PRIVATE_KEY;
    return await importJWK(jsonData, process.env.RELYING_PARTY_CLIENT_ASSERTION_SIGNING_ALG);
  } catch (e) {
    return e;
  }
}
// Function to load the private key for DECRYPTION
async function loadPrivateKeyForJWE() {
    try {
      var publicKey = process.env.RELYING_PARTY_PUBLIC_KEY_ENC.replace(/\n/g, "\r\n");
      const key = await JWK.asKey(publicKey, "pem");
      var jsonData = key.toJSON();
      jsonData.d = process.env.RELYING_PARTY_PRIVATE_KEY_ENC;
      return await importJWK(jsonData, process.env.RELYING_PARTY_PRIVATE_KEY_ENC_ALG);
    } catch (e) {
      return e;
    }
  }

// Function to load the RS256 private key
async function loadRS256PrivateKey() {
  try {
    var privateKey = process.env.INTERMEDIARY_PRIVATE_KEY.replace(/\n/g, "\r\n");
    var key = await importPKCS8(privateKey, process.env.INTERMEDIARY_SIGNING_ALG);
    return key;
  } catch (e) {
    console.log(e);
    return e;
  }
}

// Function to load the public key of IDP
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

// Function to generate a client_assertion (JWT) for client authentication
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

// Function to generate an RS256 token by the intermediary
async function generateRS256Token(payload) {
  if (payload.nonce) delete payload.nonce;
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


async function decryptJWE(jwe) {
    var privateKeyEnc= "-----BEGIN EC PRIVATE KEY-----\nMHcCAQEEICc21VTwbHZrTUcgCoswXes+aS8t7GWqQH8CcAzVpkGzoAoGCCqGSM49\nAwEHoUQDQgAEVexWR3Lb2dmnzuZeSNzS58XtM6bFpJOr2QN+p/WKN4/vHtXLBzLy\npmoTdIho/4rsUCCsIQIon/GjGv7NzpaLhg==\n-----END EC PRIVATE KEY-----\n"

    privateKeyEnc = privateKeyEnc.replace(/\n/g,"\r\n");
    var keystore = JWK.createKeyStore();
     //var key2 = await JWK.asKey(privateKey,"pem");     
    await keystore.add(privateKeyEnc, "pem" , {"use" : "enc","alg": "ECDH-ES+A128KW"});
    console.log(keystore.toJSON(true));
    const issuer = await Issuer.discover(`https://login.pushp.me`);
    const client = new issuer.Client({
        client_id: "client_pkce_pk_jwt_ES256",
        token_endpoint_auth_method: 'private_key_jwt',
        redirect_uris: ["https://jwt.io"],
        id_token_signed_response_alg : 'ES256',
        id_token_encrypted_response_alg : 'ECDH-ES+A128KW',
        id_token_encrypted_response_enc :'A128CBC-HS256'

    }, keystore.toJSON(true));

    //idToken, expectedAlg, expectedEnc
    const idToken = await client.decryptJWE(jwe,'ECDH-ES+A128KW','A128CBC-HS256');
    console.log(idToken);
    return idToken;

  }
