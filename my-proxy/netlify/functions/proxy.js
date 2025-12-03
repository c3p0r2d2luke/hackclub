const fetch = require('node-fetch');

function rewriteHTML(html, baseUrl) {
    const encode = encodeURIComponent;

    html = html.replace(
        /(href|src|action)=["']([^"']+)["']/gi,
        (match, attr, value) => {
            if (value.startsWith('http')) {
                return `${attr}="/proxy?url=${encode(value)}"`;
            }
            if (value.startsWith('//')) {
                return `${attr}="/proxy?url=${encode("https:" + value)}"`;
            }
            if (value.startsWith('#')) return match;
            const abs = new URL(value, baseUrl).href;
            return `${attr}="/proxy?url=${encode(abs)}"`;
        }
    );

    html = html.replace(
        /url\(["']?([^"')]+)["']?\)/gi,
        (match, value) => {
            if (value.startsWith('http')) {
                return `url("/proxy?url=${encode(value)}")`;
            }
            const abs = new URL(value, baseUrl).href;
            return `url("/proxy?url=${encode(abs)}")`;
        }
    );

    return html;
}

exports.handler = async function(event) {
    const url = event.queryStringParameters?.url;
    if (!url) return { statusCode: 400, body: 'Missing url' };

    const res = await fetch(url);
    const type = res.headers.get("content-type") || "";
    const baseUrl = url;

    if (type.includes("text/html")) {
        let html = await res.text();
        html = rewriteHTML(html, baseUrl);

        return {
            statusCode: 200,
            headers: { "content-type": "text/html" },
            body: html
        };
    }

    const buf = Buffer.from(await res.arrayBuffer());
    return {
        statusCode: 200,
        headers: { "content-type": type },
        body: buf.toString("base64"),
        isBase64Encoded: true
    };
};
