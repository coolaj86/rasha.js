Placeholder

I've just completed these:

* [ECDSA-CSR.js](https://git.coolaj86.com/coolaj86/ecdsa-csr.js)
* [eckles.js](https://git.coolaj86.com/coolaj86/eckles.js) - JWK-to-PEM and PEM-to-JWK for EC / ECDSA P-256 and P-384

I've got working prototypes for the RSA variants as well and I'm in the middle of cleaning them up to publish.

Testing
-------

```
openssl genrsa -out privkey-rsa-2048.pkcs1.pem 2048
openssl rsa -in privkey-rsa-2048.pkcs1.pem -pubout -out pub-rsa-2048.spki.pem
openssl pkcs8 -topk8 -nocrypt -in privkey-rsa-2048.pkcs1.pem -out privkey-rsa-2048.pkcs8.pem
openssl rsa -in pub-rsa-2048.spki.pem -pubin -RSAPublicKey_out -out pub-rsa-2048.pkcs1.pem
ssh-keygen -f ./pub-rsa-2048.spki.pem -i -mPKCS8 > ./pub-rsa-2048.ssh.pub
```

** unified openssl commands **

https://gist.github.com/briansmith/2ee42439923d8e65a266994d0f70180b
