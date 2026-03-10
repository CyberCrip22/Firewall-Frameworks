import socket
import threading
from datetime import datetime
import ipaddress
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import time
from collections import defaultdict
import json
import os

class FirewallGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Firewall Monitor - Interface Gráfica")
        self.root.geometry("900x700")
        self.root.configure(bg='#2b2b2b')
        
        # Configurações do firewall
        self.firewall = FirewallBasico()
        self.monitorando = False
        self.portas_selecionadas = [80, 443, 8080, 22, 21]
        
        # Configurar estilo
        self.setup_styles()
        
        # Criar interface
        self.criar_interface()
        
        # Carregar configurações
        self.carregar_config()
        
    def setup_styles(self):
        """Configura estilos da interface"""
        style = ttk.Style()
        style.theme_use('clam')
        
        # Cores
        self.cor_fundo = '#2b2b2b'
        self.cor_texto = '#ffffff'
        self.cor_destaque = '#404040'
        self.cor_alerta = '#ff6b6b'
        self.cor_sucesso = '#51cf66'
        
    def criar_interface(self):
        """Cria todos os elementos da interface"""
        
        # Frame principal
        main_frame = tk.Frame(self.root, bg=self.cor_fundo)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # ========== CABEÇALHO ==========
        cabecalho = tk.Frame(main_frame, bg=self.cor_destaque, height=60)
        cabecalho.pack(fill=tk.X, pady=(0, 10))
        cabecalho.pack_propagate(False)
        
        titulo = tk.Label(cabecalho, text="🛡️ FIREWALL MONITOR", 
                         font=('Arial', 18, 'bold'), 
                         bg=self.cor_destaque, fg=self.cor_texto)
        titulo.pack(side=tk.LEFT, padx=20, pady=15)
        
        # Status
        self.status_label = tk.Label(cabecalho, text="● DESLIGADO", 
                                    font=('Arial', 12, 'bold'),
                                    bg=self.cor_destaque, fg='red')
        self.status_label.pack(side=tk.RIGHT, padx=20, pady=15)
        
        # ========== PAINEL DE CONTROLE ==========
        controle_frame = tk.LabelFrame(main_frame, text=" Controles ", 
                                      bg=self.cor_fundo, fg=self.cor_texto,
                                      font=('Arial', 10, 'bold'))
        controle_frame.pack(fill=tk.X, pady=5)
        
        # Portas
        portas_frame = tk.Frame(controle_frame, bg=self.cor_fundo)
        portas_frame.pack(pady=10)
        
        tk.Label(portas_frame, text="Portas para monitorar:", 
                bg=self.cor_fundo, fg=self.cor_texto).pack(side=tk.LEFT, padx=5)
        
        self.portas_entry = tk.Entry(portas_frame, width=30, bg='#404040', 
                                     fg='white', insertbackground='white')
        self.portas_entry.pack(side=tk.LEFT, padx=5)
        self.portas_entry.insert(0, "80,443,8080,22,21")
        
        # Botões
        botoes_frame = tk.Frame(controle_frame, bg=self.cor_fundo)
        botoes_frame.pack(pady=10)
        
        self.btn_iniciar = tk.Button(botoes_frame, text="▶ INICIAR MONITORAMENTO", 
                                     command=self.iniciar_monitoramento,
                                     bg='#51cf66', fg='black', font=('Arial', 10, 'bold'),
                                     padx=20, pady=5)
        self.btn_iniciar.pack(side=tk.LEFT, padx=5)
        
        self.btn_parar = tk.Button(botoes_frame, text="⏹ PARAR", 
                                   command=self.parar_monitoramento,
                                   bg='#ff6b6b', fg='black', font=('Arial', 10, 'bold'),
                                   padx=20, pady=5, state=tk.DISABLED)
        self.btn_parar.pack(side=tk.LEFT, padx=5)
        
        self.btn_limpar = tk.Button(botoes_frame, text="🗑 LIMPAR LOG", 
                                    command=self.limpar_log,
                                    bg='#404040', fg='white', font=('Arial', 10),
                                    padx=20, pady=5)
        self.btn_limpar.pack(side=tk.LEFT, padx=5)
        
        # ========== ÁREA DE LOG ==========
        log_frame = tk.LabelFrame(main_frame, text=" Log de Tentativas ", 
                                 bg=self.cor_fundo, fg=self.cor_texto,
                                 font=('Arial', 10, 'bold'))
        log_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        # Text area com scroll
        self.log_area = scrolledtext.ScrolledText(log_frame, 
                                                  wrap=tk.WORD,
                                                  width=80, 
                                                  height=15,
                                                  bg='#1e1e1e',
                                                  fg='#00ff00',
                                                  font=('Courier', 10))
        self.log_area.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # ========== PAINEL DE ESTATÍSTICAS ==========
        stats_frame = tk.LabelFrame(main_frame, text=" Estatísticas ", 
                                   bg=self.cor_fundo, fg=self.cor_texto,
                                   font=('Arial', 10, 'bold'))
        stats_frame.pack(fill=tk.X, pady=5)
        
        # Frame para métricas
        metricas_frame = tk.Frame(stats_frame, bg=self.cor_fundo)
        metricas_frame.pack(fill=tk.X, pady=5)
        
        # Total de tentativas
        tk.Label(metricas_frame, text="Total de Tentativas:", 
                bg=self.cor_fundo, fg=self.cor_texto).grid(row=0, column=0, padx=10, pady=2, sticky='w')
        self.total_label = tk.Label(metricas_frame, text="0", 
                                   bg=self.cor_fundo, fg='#00ff00', font=('Arial', 12, 'bold'))
        self.total_label.grid(row=0, column=1, padx=10, pady=2, sticky='w')
        
        # IPs únicos
        tk.Label(metricas_frame, text="IPs Únicos:", 
                bg=self.cor_fundo, fg=self.cor_texto).grid(row=1, column=0, padx=10, pady=2, sticky='w')
        self.ips_unicos_label = tk.Label(metricas_frame, text="0", 
                                        bg=self.cor_fundo, fg='#00ff00', font=('Arial', 12, 'bold'))
        self.ips_unicos_label.grid(row=1, column=1, padx=10, pady=2, sticky='w')
        
        # Blacklist
        tk.Label(metricas_frame, text="IPs na Blacklist:", 
                bg=self.cor_fundo, fg=self.cor_texto).grid(row=2, column=0, padx=10, pady=2, sticky='w')
        self.blacklist_label = tk.Label(metricas_frame, text="0", 
                                       bg=self.cor_fundo, fg='#ff6b6b', font=('Arial', 12, 'bold'))
        self.blacklist_label.grid(row=2, column=1, padx=10, pady=2, sticky='w')
        
        # ========== LISTA DE BLACKLIST ==========
        blacklist_frame = tk.LabelFrame(main_frame, text=" Blacklist ", 
                                       bg=self.cor_fundo, fg=self.cor_texto,
                                       font=('Arial', 10, 'bold'))
        blacklist_frame.pack(fill=tk.X, pady=5)
        
        # Treeview para blacklist
        colunas = ('IP', 'Tentativas', 'Última Tentativa', 'Status')
        self.blacklist_tree = ttk.Treeview(blacklist_frame, columns=colunas, show='headings', height=4)
        
        # Configurar colunas
        self.blacklist_tree.heading('IP', text='IP')
        self.blacklist_tree.heading('Tentativas', text='Tentativas')
        self.blacklist_tree.heading('Última Tentativa', text='Última Tentativa')
        self.blacklist_tree.heading('Status', text='Status')
        
        # Larguras
        self.blacklist_tree.column('IP', width=150)
        self.blacklist_tree.column('Tentativas', width=80)
        self.blacklist_tree.column('Última Tentativa', width=150)
        self.blacklist_tree.column('Status', width=80)
        
        # Scrollbar
        scrollbar = ttk.Scrollbar(blacklist_frame, orient=tk.VERTICAL, command=self.blacklist_tree.yview)
        self.blacklist_tree.configure(yscrollcommand=scrollbar.set)
        
        self.blacklist_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
    def iniciar_monitoramento(self):
        """Inicia o monitoramento do firewall"""
        try:
            # Pegar portas do input
            portas_str = self.portas_entry.get()
            portas = [int(p.strip()) for p in portas_str.split(',')]
            
            # Atualizar firewall
            self.firewall = FirewallBasico(portas=portas, gui=self)
            self.firewall.portas = portas
            self.monitorando = True
            
            # Atualizar interface
            self.status_label.config(text="● LIGADO", fg='#51cf66')
            self.btn_iniciar.config(state=tk.DISABLED)
            self.btn_parar.config(state=tk.NORMAL)
            
            # Iniciar monitoramento em thread separada
            thread = threading.Thread(target=self.firewall.iniciar, daemon=True)
            thread.start()
            
            # Iniciar atualização da interface
            self.atualizar_interface()
            
            self.log("🚀 Monitoramento iniciado!")
            self.log(f"📡 Portas monitoradas: {portas}")
            
        except Exception as e:
            messagebox.showerror("Erro", f"Erro ao iniciar monitoramento: {e}")
    
    def parar_monitoramento(self):
        """Para o monitoramento"""
        self.monitorando = False
        self.firewall.monitorando = False
        self.status_label.config(text="● DESLIGADO", fg='red')
        self.btn_iniciar.config(state=tk.NORMAL)
        self.btn_parar.config(state=tk.DISABLED)
        self.log("⏹ Monitoramento parado.")
    
    def limpar_log(self):
        """Limpa a área de log"""
        self.log_area.delete(1.0, tk.END)
        if hasattr(self.firewall, 'conexoes'):
            self.firewall.conexoes.clear()
        self.atualizar_estatisticas()
    
    def log(self, mensagem):
        """Adiciona mensagem ao log"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.log_area.insert(tk.END, f"[{timestamp}] {mensagem}\n")
        self.log_area.see(tk.END)
    
    def log_conexao(self, ip, porta, porta_origem):
        """Registra tentativa de conexão no log"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        cor = '\033[91m' if ip in self.firewall.blacklist else '\033[93m'
        mensagem = f"🚨 CONEXÃO DETECTADA! IP: {ip} | Porta Destino: {porta} | Porta Origem: {porta_origem}"
        self.log_area.insert(tk.END, f"[{timestamp}] {mensagem}\n", ('alerta' if ip in self.firewall.blacklist else 'aviso'))
        self.log_area.see(tk.END)
    
    def atualizar_interface(self):
        """Atualiza elementos da interface periodicamente"""
        if self.monitorando:
            self.atualizar_estatisticas()
            self.atualizar_blacklist()
            self.root.after(1000, self.atualizar_interface)
    
    def atualizar_estatisticas(self):
        """Atualiza as estatísticas na interface"""
        if hasattr(self.firewall, 'conexoes'):
            total = sum(self.firewall.conexoes.values())
            ips_unicos = len(self.firewall.conexoes)
            blacklist = len(self.firewall.blacklist)
            
            self.total_label.config(text=str(total))
            self.ips_unicos_label.config(text=str(ips_unicos))
            self.blacklist_label.config(text=str(blacklist))
    
    def atualizar_blacklist(self):
        """Atualiza a lista de blacklist"""
        # Limpar treeview
        for item in self.blacklist_tree.get_children():
            self.blacklist_tree.delete(item)
        
        # Adicionar IPs da blacklist
        if hasattr(self.firewall, 'blacklist'):
            for ip in self.firewall.blacklist:
                if ip in self.firewall.conexoes:
                    tentativas = self.firewall.conexoes[ip]
                    ultima = datetime.now().strftime("%H:%M:%S")
                    self.blacklist_tree.insert('', tk.END, values=(ip, tentativas, ultima, '🚫 BLOQUEADO'))
    
    def carregar_config(self):
        """Carrega configurações salvas"""
        try:
            if os.path.exists('firewall_config.json'):
                with open('firewall_config.json', 'r') as f:
                    config = json.load(f)
                    if 'portas' in config:
                        self.portas_entry.delete(0, tk.END)
                        self.portas_entry.insert(0, ','.join(map(str, config['portas'])))
        except:
            pass
    
    def salvar_config(self):
        """Salva configurações"""
        try:
            config = {
                'portas': [int(p.strip()) for p in self.portas_entry.get().split(',')]
            }
            with open('firewall_config.json', 'w') as f:
                json.dump(config, f)
        except:
            pass

class FirewallBasico:
    def __init__(self, host='0.0.0.0', portas=None, gui=None):
        self.host = host
        self.portas = portas or [80, 443, 8080, 22, 21]
        self.blacklist = set()
        self.conexoes = defaultdict(int)
        self.ultimas_conexoes = {}
        self.monitorando = True
        self.gui = gui
        self.sockets = []
        
    def analisar_ip(self, ip):
        """Analisa se o IP é suspeito"""
        try:
            ipaddress.ip_address(ip)
            if ip.startswith(('127.', '192.168.', '10.', '172.16.')):
                return False
            return True
        except:
            return False
    
    def monitorar_porta(self, porta):
        """Monitora tentativas de conexão em uma porta"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((self.host, porta))
            sock.listen(5)
            sock.settimeout(1.0)  # Timeout para poder verificar self.monitorando
            self.sockets.append(sock)
            
            if self.gui:
                self.gui.log(f"📡 Monitorando porta {porta}...")
            
            while self.monitorando:
                try:
                    cliente, endereco = sock.accept()
                    ip_cliente = endereco[0]
                    porta_cliente = endereco[1]
                    
                    if self.analisar_ip(ip_cliente):
                        # Registra tentativa
                        self.conexoes[ip_cliente] += 1
                        self.ultimas_conexoes[ip_cliente] = datetime.now()
                        
                        # Mostra no GUI
                        if self.gui:
                            self.gui.log_conexao(ip_cliente, porta, porta_cliente)
                        
                        # Adiciona à blacklist após 3 tentativas
                        if self.conexoes[ip_cliente] >= 3:
                            self.blacklist.add(ip_cliente)
                            if self.gui:
                                self.gui.log(f"🚫 IP {ip_cliente} adicionado à blacklist!")
                    
                    cliente.close()
                    
                except socket.timeout:
                    continue
                except Exception as e:
                    if self.monitorando:  # Só log se ainda estiver monitorando
                        if self.gui:
                            self.gui.log(f"⚠️ Erro na porta {porta}: {e}")
                    
        except Exception as e:
            if self.monitorando and self.gui:
                self.gui.log(f"❌ Erro ao monitorar porta {porta}: {e}")
    
    def iniciar(self):
        """Inicia o monitoramento"""
        self.monitorando = True
        threads = []
        
        for porta in self.portas:
            thread = threading.Thread(target=self.monitorar_porta, args=(porta,))
            thread.daemon = True
            thread.start()
            threads.append(thread)
        
        # Mantém as threads rodando
        for thread in threads:
            thread.join()
    
    def parar(self):
        """Para o monitoramento"""
        self.monitorando = False
        for sock in self.sockets:
            try:
                sock.close()
            except:
                pass

if __name__ == "__main__":
    root = tk.Tk()
    app = FirewallGUI(root)
    
    # Configurar tags de cores para o log
    app.log_area.tag_config('alerta', foreground='#ff6b6b', font=('Courier', 10, 'bold'))
    app.log_area.tag_config('aviso', foreground='#ffd43b')
    
    # Salvar config ao fechar
    def on_closing():
        app.salvar_config()
        root.destroy()
    
    root.protocol("WM_DELETE_WINDOW", on_closing)
    
    root.mainloop()