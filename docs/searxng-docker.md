# Busca automática de dorks com SearXNG local

O RavenEye pode enviar as buscas geradas para uma instância SearXNG local em Docker. O endereço padrão é `http://127.0.0.1:8080`. O cliente só aceita uma URL HTTP com endereço IP de loopback e não segue redirecionamentos; respostas de outros domínios são descartadas.

O Compose fixa a imagem `2026.10.4-d48c4b555` pelo digest publicado no GHCR em 7 de outubro de 2026. SearXNG é uma rolling release; para atualizar, confira a [documentação oficial de instalação/atualização](https://docs.searxng.org/admin/installation-docker) e a [lista oficial de imagens e digests](https://github.com/searxng/searxng/pkgs/container/searxng/versions), revise a configuração e então atualize tag e digest juntos no Compose. Isso evita que `latest` altere o serviço sem revisão.

## Iniciar o serviço

Com Docker Compose instalado, gere um segredo local e inicie o serviço:

```sh
cd deploy/searxng
(umask 077; python3 -c "import secrets; print('SEARXNG_SECRET=' + secrets.token_hex(32))" > .env)
docker compose up -d
```

O Compose publica a porta apenas em `127.0.0.1`, habilita o formato JSON usado pelo RavenEye e desativa os access logs do Granian. A rotação do runtime é limitada a três arquivos de até 10 MB cada. A instância precisa consultar mecanismos de busca externos para obter resultados; apenas a conexão entre RavenEye e SearXNG fica local.

Confirme a API JSON:

```sh
curl --data-urlencode 'q=site:example.org' --data 'format=json' \\
  'http://127.0.0.1:8080/search'
```

Na configuração do RavenEye, a opção `31` define a URL local e a opção `21` seleciona `searxng`. No menu Google Hacking, escolha `2` para uma busca interativa. A opção `none` mantém a busca automática desligada durante scans integrados; `google_cse` preserva o provedor anterior.

## Privacidade e triagem

O RavenEye envia consultas por POST no corpo do formulário, então elas não aparecem na URL do access log. O Granian não grava access logs e a retenção dos logs do container tem limite configurado; mensagens administrativas ou logs de engines externos ainda dependem de cada engine. A consulta não é gravada nos logs e relatórios do RavenEye. Se o mecanismo devolver a consulta refletida em título ou trecho, ela é substituída por um marcador; uma URL que a repita é descartada e contada separadamente. Os arquivos guardam respostas em escopo (título, URL, trecho redigido e sinais de classificação), a fonte e contagens. URLs fora do domínio exato ou de seus subdomínios são ignoradas. Padrões comuns de chaves e senhas são redigidos dos trechos.

Scans integrados também escrevem essas respostas como eventos `search.response` em `<base>_events.jsonl`; o esquema e os eventos de vulnerabilidade estão em [scan-event-log-v1.md](scan-event-log-v1.md). Os eventos do scanner separam resultados confirmados dos candidatos possíveis ou prováveis.

POST evita expor o corpo em URLs e access logs comuns, mas o processo SearXNG recebe o conteúdo da consulta e as engines habilitadas podem encaminhá-lo aos provedores externos. Não trate o serviço local como anonimização.

O RavenEye retém resultados em escopo de baixa confiança para preservar recall; confiança alta exige sinais mais específicos. Isso não confirma uma vulnerabilidade. Verifique a página antes de reportar. A instância local não controla políticas de logging dos mecanismos de busca externos habilitados no SearXNG.

Para encerrar:

```sh
docker compose down
```
