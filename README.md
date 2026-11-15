# Smart Gaming Manager

Programa gratuito para **Windows** que mostra o que está rodando no seu computador, **explica cada processo em
linguagem simples** e deixa **você** escolher, um por um, quais aplicativos opcionais fechar antes de jogar. Foi feito
pensando em **Free Fire rodando em emuladores Android**, mas serve para qualquer jogo.

**Leia antes de usar**
- O programa **fecha aplicativos** quando você manda. **Dados não salvos** neles podem ser perdidos, principalmente se
  você usar FORÇAR.
- Ele **não garante aumento de FPS**. Mostra o uso de RAM e CPU e libera o que você escolher fechar.
- Projeto independente. **Não é afiliado** à Garena, ao Free Fire, à Microsoft nem a nenhum fabricante de emulador.
- Uso por sua conta e risco (veja a licença).

## Baixar e abrir
1. Em **Releases**, baixe o arquivo `SmartGamingManager_vX.Y.Z.zip`.
2. Recomendado: confira o código de verificação (SHA256) que está na página da release:
   ```powershell
   Get-FileHash .\SmartGamingManager_vX.Y.Z.zip -Algorithm SHA256
   ```
3. Extraia e abra `SmartGamingManager.exe`. **Não precisa instalar nem de administrador.**
4. O Windows pode mostrar um aviso (SmartScreen), porque o programa não tem assinatura de editor. Se você confia no
   arquivo, clique em **Mais informações, depois Executar assim mesmo**.
   **Nunca desative o antivírus para usar o programa.**

## Como usar
1. Abra o emulador (e o jogo) e depois o Smart Gaming Manager.
2. Clique em **OTIMIZAR PARA JOGOS**. O programa detecta o emulador, mostra o que está protegido e lista só os
   aplicativos que mais consomem recursos.
3. **DETALHES** explica cada aplicativo. **ENCERRAR** abre uma confirmação: primeiro um pedido normal de fechamento
   (como clicar no X); só se não funcionar você decide se quer forçar.
4. **GERAR RELATÓRIO** mostra o que foi encerrado e o antes e depois de CPU e RAM. Só grava arquivo se você clicar em
   SALVAR EM ARQUIVO.

## Se algo der errado
Clique em **INFO PARA SUPORTE**, copie o texto e envie junto com: a versão do Windows, qual emulador você usa e o que
aconteceu (um print ajuda). O texto **não inclui nomes de programas, caminhos nem o seu usuário**. Se aparecer uma
janela de erro, copie o texto dela também.

## O que ele faz e o que nunca faz
- **Nunca encerra:** processos do Windows, drivers, áudio, rede, antivírus, o emulador, o próprio programa nem
  processos desconhecidos. Na dúvida, protege.
- **Não altera:** Registro, serviços, drivers, prioridades, inicialização, nem apaga arquivos.
- **Não usa a internet** e não envia dados para lugar nenhum.
- **Não pede administrador.** Se um processo exigir privilégio, o programa avisa e não tenta.
- Verifica a **assinatura digital** dos arquivos (lendo, com o próprio Windows) para saber se um programa é quem diz ser.

## Limitações conhecidas
- Testado principalmente com o **MSI App Player**. Outros emuladores (BlueStacks, LDPlayer, GameLoop, Nox, MEmu) são
  reconhecidos por nome e pasta, mas foram menos testados.
- O jogo roda dentro do emulador, então o programa não enxerga dentro dele: ele protege o emulador inteiro.
- "Inicia com o Windows" só lê as chaves de inicialização do Registro (não cobre a pasta Inicializar nem tarefas
  agendadas).
- Aplicativos da Microsoft Store muitas vezes não aceitam o pedido normal de fechar.
- Ainda não mostra os ícones dos aplicativos.

## Rodar pelo código
```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python main.py
```
Testes de segurança e auditoria no seu PC (somente leitura):
```powershell
python -m unittest discover -s tests -v
python safety_audit.py
```
Gerar o `.exe`:
```powershell
python -m pip install pyinstaller
pyinstaller --noconfirm --clean --onefile --windowed --name SmartGamingManager --collect-all customtkinter main.py
```

## Licença e créditos
Código sob licença MIT (arquivo `LICENSE`). Usa `psutil`, `customtkinter` e outras bibliotecas, listadas em
`THIRD_PARTY_NOTICES.md`. O `.exe` é gerado com PyInstaller e inclui o Python e o Tcl/Tk.