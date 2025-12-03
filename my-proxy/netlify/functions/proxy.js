const fetch = require('node-fetch');

exports.handler = async function(event) {
    const { url } = event.queryStringParameters || {};

    if (!url) {
        return { statusCode: 400, body: 'Error: Please provide a "url" query parameter.' };
    }

    if (url.startsWith('http://localhost') || url.startsWith('127.0.0.1')) {
        return { statusCode: 403, body: 'Error: Access to localhost is forbidden.' };
    }

    try {
        const response = await fetch(url);
        const arrayBuffer = await response.arrayBuffer();

        const headers = {};
        response.headers.forEach((v, n) => {
            if (!['content-encoding', 'content-length', 'connection', 'transfer-encoding'].includes(n)) {
                headers[n] = v;
            }
        });

        return {
            statusCode: 200,
            headers,
            body: Buffer.from(arrayBuffer).toString("base64"),
            isBase64Encoded: true
        };
    } catch (err) {
        return { statusCode: 500, body: 'Error fetching URL: ' + err.message };
    }
};
