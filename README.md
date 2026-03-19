⚡ Funcionalidades

-  Monitoramento simultâneo de múltiplas portas (TCP)
-  Detecção automática de scanners de porta
-  Blacklist dinâmica (3 tentativas = bloqueio)
-  Interface gráfica profissional com tema escuro
-  Logs em tempo real com código de cores
-  Estatísticas de tráfego e IPs únicos
-  Persistência de configurações
-  Threading para performance máxima

## 🛠️Tecnologias
- **Python 3.8+**
- **Socket Programming** 
- **Threading** 
- **Tkinter** 
- **ipaddress** 
- **JSON** 

##  Arquitetura
O sistema utiliza uma arquitetura multithread onde cada porta monitorada roda 
em sua própria thread, garantindo que o firewall não perca nenhuma tentativa 
de conexão enquanto mantém a interface responsiva.

##  Como executar
```bash
git clone https://github.com/seuuser/firewall-monitor
cd firewall-monitor
python "Framework Monitor.py"
