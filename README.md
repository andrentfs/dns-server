# DNS Server Didatico

Este projeto e um pequeno resolvedor DNS escrito em Go. Ele foi criado para mostrar, de forma simples, como uma consulta DNS pode ser resolvida passo a passo.

Quando um cliente pergunta por um dominio, o programa recebe o pacote DNS, le a pergunta e tenta encontrar a resposta consultando outros servidores DNS. A ideia e demonstrar o caminho que um resolvedor recursivo faz:

1. Recebe a pergunta do cliente, por exemplo `www.google.com` do tipo `A`.
2. Pergunta primeiro para servidores raiz.
3. Le a resposta e procura indicacoes de proximos servidores na secao `AUTHORITY`.
4. Procura os IPs desses servidores na secao `ADDITIONAL`, tambem chamados de glue records.
5. Consulta o proximo servidor DNS indicado.
6. Repete o processo ate encontrar uma resposta autoritativa.
7. Devolve a resposta para o cliente.

O programa imprime logs de debug em portugues para ajudar no aprendizado. Esses logs mostram as partes internas de uma consulta DNS, incluindo:

- `QUESTION`: a pergunta feita.
- `ANSWER`: respostas diretas para a pergunta.
- `AUTHORITY`: servidores responsaveis pela proxima zona DNS.
- `ADDITIONAL`: informacoes extras, normalmente IPs dos servidores citados em `AUTHORITY`.

## Como executar

Por padrao, o servidor escuta na porta UDP `53`:

```bash
go run ./cmd/dns-resolver
```

Em muitos sistemas, a porta `53` exige permissao de administrador. Se necessario:

```bash
sudo go run ./cmd/dns-resolver
```

Depois, em outro terminal, voce pode testar com `dig` apontando para o servidor local:

```bash
dig @127.0.0.1 www.google.com A
```

Tambem e possivel consultar outros tipos de registro:

```bash
dig @127.0.0.1 google.com MX
dig @127.0.0.1 google.com NS
```

## Limitacoes

Este e um resolvedor didatico, nao um DNS pronto para producao. Ele ainda tem algumas limitacoes:

- nao implementa cache;
- nao valida DNSSEC;
- nao trata todos os casos do protocolo DNS;
- usa glue records IPv4 (`A`) para continuar a resolucao;
- nao resolve separadamente o nome de um nameserver quando a resposta nao traz o IP em `ADDITIONAL`.

Mesmo com essas limitacoes, ele e util para visualizar o funcionamento basico do DNS e entender como um resolvedor sai dos servidores raiz ate chegar a uma resposta final.
