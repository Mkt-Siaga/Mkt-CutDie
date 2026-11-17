# Mkt-CutDie

Controle de facas (cut dies) e fichas técnicas do Grupo Siaga.

Todo o conteúdo fica em `v/` cifrado com AES-256-GCM. A chave só é liberada com a senha de acesso (PBKDF2-SHA256, 600 mil iterações), no próprio navegador. Sem a senha, os arquivos deste repositório não revelam produtos, fichas ou facas.

## Atualizar o conteúdo

As fontes ficam na máquina de quem mantém o sistema, em `_fonte/`, que não vai para o repositório:

- `_fonte/facas/`: PDFs das facas
- `_fonte/fichas/`: fichas em PDF já diagramadas
- `_fonte/img/`: imagens por família
- `_fonte/SENHA.txt` e `_fonte/chave-dados.bin`: senha e chave de dados

Os dados dos produtos vêm da base de iluminação Siaga, do export GS1 e do índice de fotos Siaga.

```
node _fonte/build.mjs              # regera v/ com a senha atual
node _fonte/build.mjs "nova senha" # troca a senha
```

Depois, faça commit e push de `v/`.
