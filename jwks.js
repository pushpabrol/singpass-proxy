module.exports = (req, res) => {
    // Create and return a JSON Web Key Set (JWKS)
    // const jwks = {
    //   keys: [{ kty: 'RSA', use: 'sig' }],
    // };
  
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
  };
  