# SAN STORE + MongoDB

O catálogo usa a coleção `apps` no banco `san_store` (ou no banco definido em `MONGODB_DB`). A loja lê os cadastros do servidor para todos os visitantes. Novos cadastros são salvos no MongoDB pela API; a área de desenvolvedor exige uma chave de publicação.

## Segurança

- Nunca coloque `MONGODB_URI` no HTML ou no navegador. Ele fica apenas como variável de ambiente do servidor.
- Defina uma chave longa e aleatória em `APP_PUBLISH_KEY`. A mesma chave é digitada na área do desenvolvedor, e o servidor só permite publicação mediante validação.
- Publique o site e a API juntos sob o mesmo domínio e use HTTPS.
- Restrinja no MongoDB Atlas o acesso de rede ao servidor de hospedagem sempre que possível. Não deixe credenciais em repositório público.

## Rodar localmente

Requer Node.js 20 ou mais recente e um cluster MongoDB acessível.

1. Instale as dependências: `npm install`.
2. Copie `.env.example` para `.env`.
3. Preencha `MONGODB_URI`, `MONGODB_DB` e `APP_PUBLISH_KEY` em `.env` com os valores privados do seu ambiente.
4. Inicie com `npm start` e abra `http://localhost:3000`.

Não envie o arquivo `.env` para o GitHub.

## Publicar em hospedagem

Crie um serviço web Node.js a partir desta pasta. Configure `npm install` como comando de instalação e `npm start` como comando de início. No painel privado da hospedagem, defina `MONGODB_URI`, `MONGODB_DB` (opcional; padrão `san_store`) e `APP_PUBLISH_KEY`. O provedor deve encaminhar a porta fornecida na variável `PORT`.

A API oferece `GET /api/health`, `GET /api/apps` e `POST /api/apps` (protegido por chave). O card do SANBANK BR DIGITAL é inicializado no próprio catálogo; os outros apps são lidos do banco.


Deploy this repository root as a Node.js web service. Set MONGODB_URI and APP_PUBLISH_KEY as private environment variables; set MONGODB_DB=san_store. Never commit .env. The site and API are served together over HTTPS.
