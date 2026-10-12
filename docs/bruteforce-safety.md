# Auditoria de autenticação e wordlists

RavenEye mantém a opção HTTP(S) legada atrás de um preflight interativo. Ela
serve a testes autorizados em uma única origem. A confirmação do operador é
registrada em `raveneye_audit_log.txt` usando somente esquema, host e porta.
Se `scope_file` estiver configurado, o host precisa constar nesse escopo.

## Wordlists

Toda importação recebe uma categoria obrigatória:

`directories`, `subdomains`, `users`, `passwords`, `combos`, `params`,
`sensitive_files`, `endpoints_api` ou `custom:<campo>`.

O catálogo exibe nome, contagem e prefixo de hash, nunca as linhas. A origem
precisa ser arquivo regular UTF-8 de até 25 MiB e 500 mil linhas; linhas vazias
e duplicatas exatas são removidas, espaços dentro dos valores são preservados.
As cópias ficam em `$RAVENEYE_DATA_DIR/wordlists`, `$XDG_DATA_HOME/raveneye/wordlists`
ou `~/.local/share/raveneye/wordlists`, com permissões POSIX `0700/0600` quando
disponíveis. A integridade é conferida pelo SHA-256 antes do uso.

As listas Arjun que a função antiga buscava são listas de parâmetros, não de
senhas. O fallback de senha agora é classificado como `passwords` e não faz
download automático. Para consultas de parâmetros, use a categoria `params`.

### Enumeração de subdomínios

A opção 3 do menu de força bruta aceita listas da categoria `subdomains`. A
lista embutida RavenEye continua como padrão; uma lista importada pode ser
selecionada na operação ou definida na configuração, opção 39. A opção 22
persiste essa escolha. Antes de qualquer consulta DNS, o menu mostra o domínio,
a lista e a quantidade de candidatos e exige confirmação explícita. Se um
arquivo de escopo estiver configurado, cada candidato é filtrado pelo escopo;
sem arquivo de escopo, a enumeração usa o domínio informado após a confirmação.

O resolvedor valida e normaliza nomes IDNA, descarta rótulos inválidos e
duplicatas, aceita até 500 mil candidatos e consulta respostas IPv4 e IPv6. Uma
falha temporária de resolução recebe uma repetição; se continuar falhando, o
contador de itens inconclusivos é exibido no terminal. Dois nomes aleatórios ajudam a detectar
DNS wildcard: respostas que só coincidem com esses probes ficam marcadas como
`AMBÍGUO: DNS wildcard`, e resultados sem probes permitidos pelo escopo ficam
marcados como não verificados. Esses itens permanecem no relatório para revisão
manual e não são apresentados como subdomínios confirmados.

## Limites de execução HTTP(S)

- Um thread e uma conta por vez; a modalidade de usuários separados percorre
  contas sequencialmente.
- Limite global de 100 POSTs por execução; limite padrão de cinco por conta,
  configurável até 100. O valor NIST de 100 é um teto do verificador, não uma
  recomendação para o cliente.
- Delay configurável entre 1 e 60 segundos (padrão 1); timeout entre 1 e 30
  segundos (padrão 8); resposta limitada a 2 MiB.
- `stop-on-success` é obrigatório. Não há retry em falha de rede, 403, 423, 429,
  503 ou sinal textual de bloqueio. Um `Retry-After` não é tratado como convite
  para retomar automaticamente.
- Proxy do ambiente/configuração é ignorado; DNS é resolvido uma vez e fixado
  durante as chamadas. Redirect precisa permanecer na mesma origem. Redirect
  307/308 depois do POST é bloqueado para não repetir a credencial.
- A página GET é analisada para encontrar o formulário que contém os dois
  campos configurados. A auditoria aceita somente método POST e ação na mesma
  origem confirmada; envia os campos CSRF desse formulário e atualiza o token
  com a resposta rejeitada antes da tentativa seguinte. Ação externa ou método
  GET interrompe o fluxo antes de enviar credenciais.
- O baseline não envia POST inválido. A resposta GET fornece CSRF; sucesso exige
  um marcador configurado ausente na página inicial; quando o operador define o
  marcador, ele é o único sinal aceito. Sem marcador, um redirect de mesma
  origem continua heurístico e rotulado como `POSSIBLE`. Cookies sozinhos nunca
  confirmam uma credencial.
- O terminal e o logger não imprimem usuário ou senha. A função Python
  `bruteforce_login` preserva a tupla antiga e retorna a senha encontrada ao
  chamador por compatibilidade; integração externa deve tratá-la como segredo.
- Quando `use_extra_passwords` estiver ativo com uma lista importada, a lista
  escolhida é percorrida antes do fallback embutido, para que o limite por conta
  não esconda todos os valores selecionados.
- `BruteForceEngine.run()` e `Adapter.audit()` são a interface async para esse
  mesmo fluxo governado. Exigem `preflight_confirmed=True`, mantêm uma tentativa
  ativa por vez e aplicam os limites da `CredentialAuditPolicy`. Cancelamento
  para antes do próximo POST e aguarda a chamada em andamento terminar ou atingir
  timeout. O resultado contém apenas estado, origem, contagem, duração e taxa;
  não retorna a senha encontrada.

## Checkpoint

O checkpoint é opcional no menu. Ele é escrito atomicamente com permissão `0600`
e HMAC local. Guarda estado, índice, contagens e fingerprints autenticados; não
grava URL, usuário, senha, formulário, cookie ou resposta. Mudança de alvo,
listas, limite, delay, timeout, campos ou marcador invalida a retomada. Um
checkpoint bloqueado por sinal do servidor não pode ser retomado.

Se o processo cair durante o POST, o resultado do último item é incerto. A
retomada conta esse item como tentativa e o pula, evitando enviar a mesma
credencial duas vezes. Isso pode omitir um candidato cujo POST não chegou ao
servidor; a saída deixa essa situação registrada no checkpoint.

## Protocolos e comparação

HTTP(S) é a auditoria serial por wordlist. SSH tem uma interface de verificação
de um único par usuário/senha, exige `preflight_confirmed=True`, respeita o
escopo configurado, fixa o IP resolvido e valida a chave do host pelo
`known_hosts` padrão do AsyncSSH (ou pelo arquivo explicitamente fornecido).
Não executa comandos remotos, não percorre wordlists e ainda não está conectado
ao menu. FTP, SMB, RDP, MySQL, PostgreSQL, MongoDB, LDAP, SMTP, Redis e Telnet
continuam indisponíveis; nenhum deles abre conexão.

O adaptador SSH passou por handshake real com AsyncSSH 2.24.1 contra um servidor
efêmero em `127.0.0.1`: uma chave presente no `known_hosts` foi aceita e uma
senha incorreta foi recusada. Nenhuma conexão externa foi aberta.

### Comparação local com Hydra

O harness `benchmarks/bruteforce_comparison.py` executa somente uma fixture
HTTP rotulada em loopback, com três candidatos por cenário, um caso positivo e
um negativo, cinco repetições por ferramenta/perfil e coleta de métricas sem
persistir credenciais. O binário Hydra v9.8dev foi compilado em `/tmp` a partir
do commit `17b52613320257a620ce3b5611b2e8196eb6e7fc`; não foi instalado no
sistema. O relatório agregado está em
`benchmarks/bruteforce_comparison_baseline.json`.

| Perfil | Mediana de tentativas HTTP/s | VP | FP | FN | VN |
| --- | ---: | ---: | ---: | ---: | ---: |
| RavenEye (1 thread, 1 s entre tentativas) | 1,687 | 5 | 0 | 0 | 5 |
| Hydra (`-t 1 -c 1`) | 0,854 | 5 | 0 | 0 | 5 |
| Hydra (16 tarefas, padrão documentado) | 5,403 | 5 | 0 | 0 | 5 |

Neste fixture, RavenEye ficou cerca de 2 vezes acima do Hydra limitado ao perfil
serial medido, mas cerca de 3,2 vezes abaixo do Hydra com 16 tarefas. A amostra
de acurácia é pequena e sintética; precisão/recall 1,0 nela não demonstra
qualidade em formulários arbitrários. Portanto, o objetivo de superar Hydra em
desempenho geral **não foi atingido**. A diferença de concorrência explica parte
do resultado: RavenEye preserva uma tentativa simultânea e um segundo entre
tentativas para conter risco de lockout. Aumentar a concorrência por conta para
ganhar taxa pode causar bloqueio de contas e não foi aplicado. A taxa publicada
é parede a parede da chamada de engine/comando; os imports RavenEye já estavam
aquecidos, enquanto a inicialização do subprocesso Hydra está incluída, então a
medição curta favorece RavenEye.

O harness também inclui casos positivos e negativos com token CSRF de uso único,
renovado em cada resposta rejeitada. O cenário entrega ao Hydra o valor inicial
como campo estático e mede o comportamento após sua rotação; a RavenEye lê o
novo token do formulário retornado. A integração RavenEye desse cenário passou
em fixture HTTP efêmera de loopback. As métricas desse cenário ainda não foram
adicionadas à tabela: o executável Hydra temporário usado na rodada anterior não
está mais disponível neste ambiente para repetir a comparação. Portanto, esse
caso demonstra uma capacidade testada do fluxo, mas ainda não comprova vantagem
comparativa sobre Hydra.

Hydra oferece vários protocolos e execução paralela. O próximo passo de Fase 3
é ampliar os fixtures por tipo de formulário/sinal de sucesso, medir retomada e
erros de rede/bloqueio e só então decidir se algum perfil concorrente limitado
por conta tem uma relação risco/benefício aceitável. Katana é referência de
crawler, não de auditoria de login; sua comparação continua separada.

## Fontes

- [THC Hydra manual](https://github.com/vanhauser-thc/thc-hydra/blob/master/hydra.1)
- [OWASP Credential Stuffing Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Credential_Stuffing_Prevention_Cheat_Sheet.html)
- [OWASP Bot Management and Anti-Automation Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Bot_Management_and_Anti-Automation_Cheat_Sheet.html)
- [NIST SP 800-63B-4](https://pages.nist.gov/800-63-4/sp800-63b.html)
- [RFC 4252 — SSH Authentication Protocol](https://datatracker.ietf.org/doc/html/rfc4252)
- [Documentação oficial do AsyncSSH](https://asyncssh.readthedocs.io/en/latest/api.html)
