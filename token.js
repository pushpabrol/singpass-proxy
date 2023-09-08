const axios = require('axios');
const jwt = require('jsonwebtoken');
const { generatePrivateKeyJWT, loadPublicKey } = require('./auth-utils'); // You need to implement these functions

module.exports = async (req, res) => {
  const { client_id, client_secret, code, code_verifier, redirect_uri } = req.body;

  if (!client_id || !client_secret) {
    return res.status(400).send('Missing client_id / client_secret');
  }

  if (process.env.AUTH0_CLIENT_ID === client_id && process.env.AUTH0_CLIENT_SECRET === client_secret) {
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
          redirect_uri,
        }),
      };

      const response = await axios.request(options);
      const { id_token } = response.data;
      const publicKey = await loadPublicKey(process.env);

      const code_v = new TextEncoder().encode(code_verifier);
      const code_v_s256 = crypto.createHash('sha256').update(code_v).digest('base64').replace(/\//g, '_').replace(/\+/g, '-').replace(/=/g, '');

      console.log(`nonce expected: ${code_v_s256}`);

      const { payload, protectedHeader } = await jwt.verify(id_token, publicKey, {
        issuer: process.env.ISSUER,
        audience: process.env.CLIENT_ID,
      });

      if (payload.nonce !== code_v_s256) {
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
};
