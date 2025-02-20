const fs = require("fs");
const https = require("https");
const express = require("express");

const app = express();


// Carrega os certificados SSL
const options = {
  key: fs.readFileSync("key.pem"),
  cert: fs.readFileSync("cert.pem"),
  requestCert: true, // Solicita um certificado do cliente
  rejectUnauthorized: false, // Permite conexões sem certificado de cliente (mude para true se quiser exigir)
};

// Lista de autoridades confiáveis (opcional)
const TRUSTED_ISSUERS = ["Minha Autoridade Confiável"];

// Lista de fingerprints autorizados (opcional)
const TRUSTED_FINGERPRINTS = ["SHA256_HASH_DO_CERTIFICADO"];

app.get("/", (req, res) => {
  const cert = req.socket.getPeerCertificate();

  res.json({
    cert
  });

  return cert

   // Pega o certificado do próprio servidor
   const cert2 = req.socket.server._sharedCreds.context.getCertificate();
   const serverIssuer = req.socket.server._sharedCreds.context.getIssuer();

  console.log("📜 Informações do Certificado:", cert, req.socket.server._sharedCreds);

  if (!cert || Object.keys(cert).length === 0) {
    return res.status(403).send("Nenhum certificado foi fornecido!");
  }

   // Exibir detalhes do certificado do servidor
   const certInfo = {
    sujeito: cert.subject,
    emissor: serverIssuer,
    válido_de: cert.valid_from,
    válido_até: cert.valid_to,
    fingerprint: cert.fingerprint256,
  };

  // Exibe detalhes do certificado
//   const certInfo = {
//     sujeito: cert.subject,
//     emissor: cert.issuer,
//     válido_de: cert.valid_from,
//     válido_até: cert.valid_to,
//     fingerprint: cert.fingerprint256,
//   };

  console.log("📜 Informações do Certificado:", certInfo);

  // Verifica se o certificado é confiável
  if (cert.issuer && !TRUSTED_ISSUERS.includes(cert.issuer.O)) {
    return res.status(403).send("Certificado não confiável!");
  }

  // Verifica se o fingerprint é válido
  if (!TRUSTED_FINGERPRINTS.includes(cert.fingerprint256)) {
    return res.status(403).send("Certificado não autorizado!");
  }

  res.json({
    mensagem: "Certificado válido!",
    detalhes: certInfo,
  });
});

// Inicia o servidor HTTPS

app.server(80, () => {
  console.log("🔒 Servidor HTTPS rodando em https://localhost:80");
})
// https.createServer(options, app).listen(80, () => {
//   console.log("🔒 Servidor HTTPS rodando em https://localhost:80");
// });
