// Cloudflare Worker - Wasabi Upload Handler
// ファイル名: _worker.js

export default {
  async fetch(request, env) {
    // CORS headers
    const corsHeaders = {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type',
    };

    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: corsHeaders });
    }

    if (request.method === 'POST' && new URL(request.url).pathname === '/api/upload') {
      try {
        const formData = await request.formData();
        const file = formData.get('file');

        if (!file) {
          return new Response(JSON.stringify({ error: 'No file provided' }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' },
          });
        }

        const fileBuffer = await file.arrayBuffer();
        const fileName = file.name;
        const contentType = file.type || 'application/octet-stream';

        // Wasabi設定（環境変数から取得）
        const region = 'ap-northeast-1';
        const bucket = 'image-upload-original';
        const endpoint = `https://s3.${region}.wasabisys.com`;

        // AWS Signature V4でアップロード
        const url = `${endpoint}/${bucket}/${fileName}`;
        const signedRequest = await signRequest(
          'PUT',
          url,
          fileBuffer,
          contentType,
          region,
          env.WASABI_ACCESS_KEY,
          env.WASABI_SECRET_KEY
        );

        const uploadResponse = await fetch(signedRequest.url, {
          method: 'PUT',
          headers: signedRequest.headers,
          body: fileBuffer,
        });

        if (!uploadResponse.ok) {
          const errText = await uploadResponse.text();
          throw new Error(`Wasabi error: ${uploadResponse.status} - ${errText}`);
        }

        return new Response(JSON.stringify({ success: true, fileName }), {
          status: 200,
          headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        });

      } catch (err) {
        return new Response(JSON.stringify({ error: err.message }), {
          status: 500,
          headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        });
      }
    }

    return new Response('Not found', { status: 404 });
  }
};

// ========================================
// AWS Signature V4
// ========================================
async function signRequest(method, url, body, contentType, region, accessKey, secretKey) {
  const parsedUrl = new URL(url);
  const host = parsedUrl.host;
  const path = parsedUrl.pathname;

  const now = new Date();
  const amzDate = now.toISOString().replace(/[:\-]|\.\d{3}/g, '').slice(0, 15) + 'Z';
  const dateStamp = amzDate.slice(0, 8);

  const bodyHash = await sha256Hex(body);

  const headers = {
    'host': host,
    'x-amz-date': amzDate,
    'x-amz-content-sha256': bodyHash,
    'content-type': contentType,
  };

  const signedHeaders = Object.keys(headers).sort().join(';');
  const canonicalHeaders = Object.keys(headers).sort()
    .map(k => `${k}:${headers[k]}\n`).join('');

  const canonicalRequest = [
    method,
    path,
    '',
    canonicalHeaders,
    signedHeaders,
    bodyHash
  ].join('\n');

  const credentialScope = `${dateStamp}/${region}/s3/aws4_request`;
  const stringToSign = [
    'AWS4-HMAC-SHA256',
    amzDate,
    credentialScope,
    await sha256Hex(canonicalRequest)
  ].join('\n');

  const signingKey = await getSigningKey(secretKey, dateStamp, region, 's3');
  const signature = await hmacHex(signingKey, stringToSign);

  const authorization = `AWS4-HMAC-SHA256 Credential=${accessKey}/${credentialScope}, SignedHeaders=${signedHeaders}, Signature=${signature}`;

  return {
    url,
    headers: {
      ...headers,
      'Authorization': authorization,
    }
  };
}

async function sha256Hex(data) {
  const buffer = typeof data === 'string' ? new TextEncoder().encode(data) : data;
  const hash = await crypto.subtle.digest('SHA-256', buffer);
  return Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2, '0')).join('');
}

async function hmac(key, data) {
  const cryptoKey = await crypto.subtle.importKey(
    'raw', typeof key === 'string' ? new TextEncoder().encode(key) : key,
    { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
  );
  return crypto.subtle.sign('HMAC', cryptoKey, typeof data === 'string' ? new TextEncoder().encode(data) : data);
}

async function hmacHex(key, data) {
  const sig = await hmac(key, data);
  return Array.from(new Uint8Array(sig)).map(b => b.toString(16).padStart(2, '0')).join('');
}

async function getSigningKey(secretKey, dateStamp, region, service) {
  const kDate = await hmac(`AWS4${secretKey}`, dateStamp);
  const kRegion = await hmac(kDate, region);
  const kService = await hmac(kRegion, service);
  const kSigning = await hmac(kService, 'aws4_request');
  return kSigning;
}
