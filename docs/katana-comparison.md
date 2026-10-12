# Comparação local de crawler com Katana

O baseline repetível está em
[`benchmarks/katana_comparison_baseline.json`](../benchmarks/katana_comparison_baseline.json).
Ele compara RavenEye com Katana v1.8.0 em três execuções por ferramenta, sem
aquecimento, contra a mesma fixture rotulada em loopback. A fixture contém 200
páginas rotuladas, 100 rotas de API, três endpoints declarados em JavaScript,
pares de páginas duplicadas e 9.500 URLs de stress com resposta 404. Cada
processo recebe profundidade 3, limite de 11.000 páginas, 20 conexões globais e
limite de 200 requisições/s. Nenhum alvo externo foi acessado.

| Métrica | RavenEye | Katana v1.8.0 |
| --- | ---: | ---: |
| Mediana de páginas únicas/s | 195,64 | 166,24 |
| P95 de páginas únicas/s | 195,65 | 166,26 |
| Cobertura de páginas conhecidas | 100% | 100% |
| Cobertura de API conhecida | 100% | 100% |
| Cobertura das 9.500 rotas de stress | 100% | 100% |
| Requisições repetidas no fixture | 0 | 0 |
| Memória absoluta normalizada por 10k URLs, mediana | 87.958 KiB | 98.169 KiB |
| Memória absoluta normalizada por 10k URLs, P95 | 106.269 KiB | 98.605 KiB |
| Endpoints JS estáticos conhecidos requisitados | 3/3 | 0/3 |

Nessa fixture, RavenEye concluiu 17,7% mais páginas por segundo na mediana.
Ambos alcançaram toda a cobertura de rotas conhecidas. RavenEye também requisitou
os três endpoints estáticos definidos em JavaScript; Katana requisitou
`/assets/app.js`, mas não pediu o módulo importado nem os três endpoints usando
`-jc`, `-jsl`, `-ndef` e saída JSONL. A fixture declara esse arquivo como
`type="module"`, para que o `import` seja válido no navegador.

O consumo de memória tem um resultado misto: a mediana de RavenEye foi cerca de
10,4% menor, mas seu P95 foi 7,8% maior, por um pico em uma das três execuções.
Portanto, a amostra não sustenta uma afirmação de que RavenEye sempre consome
menos memória. A classificação de páginas de RavenEye alcançou macro F1 1,0 e a
deduplicação teve precisão e recall 1,0 nesse fixture rotulado; Katana não
fornece essas classificações neste modo. Esses valores sintéticos não estimam a
precisão em sites reais.

O modo headless não faz parte dessa comparação: a tentativa anterior do Katana
headless ficou sem conclusão confiável nesta fixture. A cobertura de chamadas
Xhr/fetch em execução dinâmica permanece sem comparação validada. O benchmark
estático não enviou requisições POST; a rota POST sintética da fixture não altera
estado.

O comparador pode ser repetido com:

```sh
python3 benchmarks/katana_comparison.py \
  --runs 3 --warmups 0 --pages 11000 --stress-urls 9500 \
  --output output/benchmarks/katana-comparison.json
```

O binário de referência foi Katana v1.8.0, release oficial publicada em 5 de
outubro de 2026: [release v1.8.0](https://github.com/projectdiscovery/katana/releases/tag/v1.8.0).
O SHA-256 do ZIP Linux x86-64 foi conferido com a lista oficial de checksums:
`cb027ae99d0757061b70c07a15c7a80f62c5a535ab52c4a329f80c4b0a7309d2`.
As opções de crawling JavaScript usadas seguem a
[documentação oficial do projeto](https://github.com/projectdiscovery/katana).
