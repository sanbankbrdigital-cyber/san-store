function registerStorePageRoutes(app, services) {
  const { findPublishedAppByPublicId, validHttpsUrl, readLimiter } = services;
  const escapeHtml = (value) => String(value == null ? '' : value).replace(/[&<>"']/g, (char) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  }[char]));

  app.get('/store/:appId', readLimiter, async (req, res) => {
    try {
      const item = await findPublishedAppByPublicId(req.params.appId);
      if (!item) return res.status(404).type('html').send('<!doctype html><meta charset="utf-8"><title>App não encontrado</title><p>Este aplicativo não está disponível na SAN STORE.</p>');
      const name = escapeHtml(item.name || 'Aplicativo SAN STORE');
      const description = escapeHtml(item.description || 'Conheça este aplicativo na SAN STORE.');
      const category = escapeHtml(item.subcategory || ('Game' === item.category ? 'Jogo' : 'Aplicativo'));
      const image = validHttpsUrl(item.image) ? escapeHtml(item.image) : '';
      const apk = validHttpsUrl(item.apk) ? escapeHtml(item.apk) : '';
      const blocked = Boolean(item.blocked);
      const install = !blocked && apk
        ? `<a class="install" href="${apk}" rel="nofollow noopener">Baixar aplicativo</a>`
        : `<div class="blocked">${blocked ? 'Downloads temporariamente indisponíveis.' : 'Link de download indisponível.'}</div>`;
      const previewImage = image ? `<img class="icon" src="${image}" alt="Ícone de ${name}">` : '<div class="icon fallback">SAN</div>';
      const html = `<!doctype html>
<html lang="pt-BR"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="theme-color" content="#101b2e"><meta property="og:type" content="website"><meta property="og:title" content="${name} · SAN STORE"><meta property="og:description" content="${description}">${image ? `<meta property="og:image" content="${image}">` : ''}
<title>${name} · SAN STORE</title><style>
*{box-sizing:border-box}body{margin:0;min-height:100vh;background:radial-gradient(circle at 20% 0%,#253d62 0,#101b2e 44%,#090f1c 100%);color:#f4f7ff;font:16px system-ui,-apple-system,Segoe UI,Roboto,sans-serif;display:grid;place-items:center;padding:24px}.card{width:min(100%,560px);padding:24px;border:1px solid #526c91;border-radius:28px;background:linear-gradient(145deg,rgba(42,65,99,.94),rgba(19,30,48,.96));box-shadow:0 22px 70px #0008}.brand{font-size:12px;letter-spacing:.15em;color:#9fe4ff;font-weight:800}.head{display:flex;align-items:center;gap:17px;margin:22px 0}.icon{width:88px;height:88px;border-radius:24px;object-fit:cover;border:1px solid #92a9cb;background:#17243b}.fallback{display:grid;place-items:center;color:#b7cbff;font-weight:900}.name{font-size:24px;font-weight:800;line-height:1.15;overflow-wrap:anywhere}.category{display:inline-block;padding:7px 12px;border-radius:99px;background:#173c49;color:#a5e1e8;font-size:12px;font-weight:700}.description{color:#c6d2e6;line-height:1.6;margin:18px 0 22px;white-space:pre-wrap}.install{display:block;text-align:center;text-decoration:none;color:#fff;font-weight:800;padding:15px 18px;border-radius:18px;background:linear-gradient(120deg,#708dff,#5b73e8);box-shadow:0 8px 24px #344b9b80}.blocked{text-align:center;border-radius:16px;padding:13px;background:#4b2830;color:#ffe0e5}.foot{text-align:center;margin:18px 0 0;color:#91a2bd;font-size:11px}
</style></head><body><main class="card"><div class="brand">SAN STORE · APPS E JOGOS</div><div class="head">${previewImage}<div class="name">${name}</div></div><span class="category">${category}</span><p class="description">${description}</p>${install}<div class="foot">Página compartilhada da SAN STORE</div></main></body></html>`;
      res.set('Cache-Control', 'public, max-age=60');
      res.set('X-Content-Type-Options', 'nosniff');
      return res.status(200).type('html').send(html);
    } catch {
      return res.status(503).type('html').send('<!doctype html><meta charset="utf-8"><title>SAN STORE</title><p>Não foi possível carregar a página agora.</p>');
    }
  });
}

module.exports = registerStorePageRoutes;
