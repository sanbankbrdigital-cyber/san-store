function registerAccountRoutes(app, services) {
  const { users, resetRequests, sessions, requireUser, requireAdmin, hashPassword, validPassword, normalizeEmail, emailPattern, ObjectId, authLimiter } = services;
  const MAX_PHOTO_BYTES = 400 * 1024;

  function validPhotoData(value) {
    if (typeof value !== 'string' || value.length > 560_000) return false;
    const match = /^data:image\/jpeg;base64,([A-Za-z0-9+/]+={0,2})$/.exec(value);
    if (!match) return false;
    const bytes = Buffer.from(match[1], 'base64');
    return bytes.length > 0 && bytes.length <= MAX_PHOTO_BYTES && bytes[0] === 0xff && bytes[1] === 0xd8 && bytes[2] === 0xff;
  }

  app.get('/api/auth/profile', requireUser, async (req, res) => {
    try {
      const user = await users().findOne({ _id: req.authUser._id }, { projection: { profilePhoto: 1 } });
      if (!user) return res.status(404).json({ error: 'Conta não encontrada.' });
      res.set('Cache-Control', 'no-store');
      return res.json({ profilePhoto: user.profilePhoto || '' });
    } catch {
      return res.status(503).json({ error: 'Não foi possível carregar a foto do perfil agora.' });
    }
  });

  app.put('/api/auth/profile/photo', requireUser, async (req, res) => {
    const profilePhoto = req.body?.profilePhoto;
    if (!validPhotoData(profilePhoto)) return res.status(400).json({ error: 'Escolha uma foto JPG válida de até 400 KB.' });
    try {
      const result = await users().updateOne({ _id: req.authUser._id }, { $set: { profilePhoto, profilePhotoUpdatedAt: new Date() } });
      if (result.matchedCount !== 1) return res.status(404).json({ error: 'Conta não encontrada.' });
      res.set('Cache-Control', 'no-store');
      return res.json({ ok: true, profilePhoto });
    } catch {
      return res.status(503).json({ error: 'Não foi possível salvar a foto do perfil agora.' });
    }
  });

  app.post('/api/auth/password-reset-requests', authLimiter, async (req, res) => {
    const email = normalizeEmail(req.body?.email);
    const newPassword = req.body?.newPassword;
    if (!emailPattern.test(email)) return res.status(400).json({ error: 'Informe o e-mail SAN STORE cadastrado.' });
    if (!validPassword(newPassword)) return res.status(400).json({ error: 'A nova senha deve ter 8 a 10 caracteres, com maiúscula, minúscula, número e caractere especial.' });
    try {
      // Hash before looking up the account so existing and unknown emails receive a similar response path.
      const newPasswordHash = await hashPassword(newPassword);
      const user = await users().findOne({ email }, { projection: { _id: 1, account: 1 } });
      if (user) {
        try {
          await resetRequests().insertOne({
            userId: user._id,
            account: user.account,
            email,
            newPasswordHash,
            status: 'pending',
            createdAt: new Date(),
          });
        } catch (error) {
          // A pending request already exists for this account. Never replace its requested password.
          if (!error || error.code !== 11000) throw error;
        }
      }
      res.set('Cache-Control', 'no-store');
      return res.status(202).json({ ok: true, message: 'Se a conta existir, a solicitação foi enviada para aprovação do administrador.' });
    } catch {
      return res.status(503).json({ error: 'Não foi possível registrar a solicitação agora. Tente novamente.' });
    }
  });

  app.get('/api/admin/password-reset-requests', requireAdmin, async (req, res) => {
    const status = req.query.status === 'all' ? 'all' : 'pending';
    try {
      const query = status === 'all' ? {} : { status: 'pending' };
      const docs = await resetRequests().find(query, {
        projection: { account: 1, email: 1, status: 1, createdAt: 1, reviewedAt: 1, reviewReason: 1 },
      }).sort({ createdAt: -1 }).limit(200).toArray();
      res.set('Cache-Control', 'no-store');
      return res.json(docs.map((item) => ({
        id: item._id.toString(), account: item.account, email: item.email,
        status: item.status, createdAt: item.createdAt || null,
        reviewedAt: item.reviewedAt || null, reviewReason: item.reviewReason || '',
      })));
    } catch {
      return res.status(503).json({ error: 'Não foi possível carregar as solicitações de senha.' });
    }
  });

  app.post('/api/admin/password-reset-requests/:id/approve', requireAdmin, async (req, res) => {
    if (!ObjectId.isValid(req.params.id)) return res.status(400).json({ error: 'Solicitação inválida.' });
    const id = new ObjectId(req.params.id);
    try {
      const request = await resetRequests().findOne({ _id: id, status: 'pending' });
      if (!request) return res.status(409).json({ error: 'A solicitação não está mais pendente.' });
      const lock = await resetRequests().updateOne(
        { _id: id, status: 'pending', reviewLock: { $ne: true } },
        { $set: { reviewLock: true, reviewedBy: req.authUser._id } },
      );
      if (lock.matchedCount !== 1) return res.status(409).json({ error: 'Outro administrador já está analisando esta solicitação.' });

      try {
        const changed = await users().updateOne(
          { _id: request.userId },
          { $set: { passwordHash: request.newPasswordHash, passwordChangedAt: new Date() } },
        );
        if (changed.matchedCount !== 1) {
          await resetRequests().updateOne({ _id: id, status: 'pending' }, { $set: { status: 'rejected', reviewedAt: new Date(), reviewReason: 'Conta não encontrada.' }, $unset: { newPasswordHash: '', reviewLock: '' } });
          return res.status(404).json({ error: 'A conta vinculada não foi encontrada; solicitação encerrada.' });
        }
        await sessions().deleteMany({ userId: request.userId });
        await resetRequests().updateOne(
          { _id: id, status: 'pending', reviewLock: true },
          { $set: { status: 'approved', reviewedAt: new Date() }, $unset: { newPasswordHash: '', reviewLock: '' } },
        );
        res.set('Cache-Control', 'no-store');
        return res.json({ ok: true, status: 'approved', message: 'Senha alterada. As sessões anteriores foram encerradas.' });
      } catch {
        await resetRequests().updateOne({ _id: id, status: 'pending' }, { $unset: { reviewLock: '', reviewedBy: '' } }).catch(() => {});
        return res.status(503).json({ error: 'Não foi possível concluir a aprovação. A solicitação permanece disponível para nova tentativa.' });
      }
    } catch {
      return res.status(503).json({ error: 'Não foi possível aprovar esta solicitação agora.' });
    }
  });

  app.post('/api/admin/password-reset-requests/:id/reject', requireAdmin, async (req, res) => {
    if (!ObjectId.isValid(req.params.id)) return res.status(400).json({ error: 'Solicitação inválida.' });
    const reason = typeof req.body?.reason === 'string' ? req.body.reason.trim().slice(0, 240) : '';
    try {
      const result = await resetRequests().updateOne(
        { _id: new ObjectId(req.params.id), status: 'pending', reviewLock: { $ne: true } },
        { $set: { status: 'rejected', reviewedAt: new Date(), reviewedBy: req.authUser._id, reviewReason: reason }, $unset: { newPasswordHash: '' } },
      );
      if (result.matchedCount !== 1) return res.status(409).json({ error: 'A solicitação não está mais pendente ou está sendo analisada.' });
      res.set('Cache-Control', 'no-store');
      return res.json({ ok: true, status: 'rejected', message: 'Solicitação recusada. A senha atual foi mantida.' });
    } catch {
      return res.status(503).json({ error: 'Não foi possível recusar esta solicitação agora.' });
    }
  });
}

module.exports = registerAccountRoutes;
