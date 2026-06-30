const admin = require('firebase-admin');
const tls = require('tls');
const https = require('https');

// Inicializa Firebase Admin com service account do GitHub Secret
const serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);
admin.initializeApp({ credential: admin.credential.cert(serviceAccount) });
const db = admin.firestore();

// Requisição HTTPS seguindo redirecionamentos (para RDAP)
function httpsGet(url, redirectsLeft = 5) {
  return new Promise((resolve, reject) => {
    const req = https.get(url, { headers: { Accept: 'application/rdap+json, application/json' } }, (res) => {
      if ((res.statusCode === 301 || res.statusCode === 302) && res.headers.location) {
        if (redirectsLeft <= 0) { reject(new Error('Muitos redirecionamentos')); return; }
        httpsGet(res.headers.location, redirectsLeft - 1).then(resolve).catch(reject);
        return;
      }
      let data = '';
      res.on('data', (chunk) => { data += chunk; });
      res.on('end', () => resolve(data));
    });
    req.on('error', reject);
    req.setTimeout(15000, () => { req.destroy(); reject(new Error('Timeout')); });
  });
}

function checkSSL(hostname) {
  return new Promise((resolve) => {
    const socket = tls.connect(
      { host: hostname, port: 443, servername: hostname, rejectUnauthorized: false },
      () => {
        const cert = socket.getPeerCertificate();
        socket.end();
        if (!cert || !cert.valid_to) {
          resolve({ error: 'Certificado não encontrado' });
          return;
        }
        const expiry = new Date(cert.valid_to);
        const daysLeft = Math.ceil((expiry - Date.now()) / 86400000);
        resolve({ expiry: expiry.toISOString(), daysLeft, issuer: cert.issuer?.O || 'Desconhecido' });
      }
    );
    socket.on('error', (err) => resolve({ error: err.message }));
    socket.setTimeout(12000, () => { socket.destroy(); resolve({ error: 'Timeout SSL' }); });
  });
}

async function checkDomainExpiry(domain) {
  try {
    const rootDomain = domain.split('.').slice(-2).join('.');
    const raw = await httpsGet(`https://rdap.org/domain/${rootDomain}`);
    const json = JSON.parse(raw);
    const expEvent = (json.events || []).find((e) => e.eventAction === 'expiration');
    if (!expEvent) return { error: 'Expiração não encontrada no RDAP' };
    const expiry = new Date(expEvent.eventDate);
    const daysLeft = Math.ceil((expiry - Date.now()) / 86400000);
    return { expiry: expiry.toISOString(), daysLeft };
  } catch (err) {
    return { error: err.message };
  }
}

async function main() {
  const snap = await db.collection('domains').get();
  if (snap.empty) {
    console.log('Nenhum domínio cadastrado.');
    process.exit(0);
  }

  console.log(`Verificando ${snap.size} domínio(s)...\n`);

  for (const doc of snap.docs) {
    const hostname = doc.data().name;
    process.stdout.write(`  ${hostname} ... `);

    const [ssl, domain] = await Promise.all([checkSSL(hostname), checkDomainExpiry(hostname)]);

    const sslDias = ssl.daysLeft ?? 9999;
    const domDias = domain.daysLeft ?? 9999;
    const minDias = Math.min(sslDias, domDias);

    let status = 'ok';
    if (ssl.error && domain.error) status = 'error';
    else if (minDias <= 7) status = 'critical';
    else if (minDias <= 30) status = 'warning';

    await doc.ref.update({ ssl, domain, status, lastChecked: admin.firestore.FieldValue.serverTimestamp() });

    const emoji = { ok: '✅', warning: '⚠️', critical: '🔴', error: '❌' }[status];
    console.log(`${emoji} ${status.toUpperCase()} | SSL: ${ssl.daysLeft ?? ssl.error} | DNS: ${domain.daysLeft ?? domain.error}`);
  }

  console.log('\nVerificação concluída.');
  process.exit(0);
}

main().catch((err) => { console.error('Erro fatal:', err); process.exit(1); });
