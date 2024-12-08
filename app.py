from flask import Flask, jsonify, request, abort
import time
import requests
from discord_webhook import DiscordEmbed, DiscordWebhook
from g4f.client import Client
from datetime import datetime, timedelta
from dateutil import parser
from werkzeug.middleware.proxy_fix import ProxyFix
from collections import defaultdict
from functools import wraps
import google.generativeai as genai



app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_host=1)

blocked_ips = {"2804:14d:ed30:80cd:c5ee:ca63:adf:aeeb", "179.105.129.63"}   

# Dicionário para armazenar os contadores de requisições por IP
ip_request_count = defaultdict(list)
# Dicionário para armazenar os tempos de expiração dos IPs bloqueados
blocked_ips = {}

# Função para verificar e bloquear IPs que excedem o limite de requisições
def check_rate_limit(ip_address):
    now = datetime.now()
    # Verifica se o IP está bloqueado
    if ip_address in blocked_ips:
        # Se ainda estiver dentro do período de bloqueio, retorna True
        if now < blocked_ips[ip_address]:
            return True
        # Se já passou o período de bloqueio, remove o IP da lista de bloqueados
        else:
            del blocked_ips[ip_address]
            ip_request_count.pop(ip_address, None)

    # Verifica se o IP excedeu o limite de requisições
    if len(ip_request_count[ip_address]) >= 5:
        # Obtém o horário da requisição mais antiga
        oldest_request_time = ip_request_count[ip_address][0]
        # Se a primeira requisição foi feita há menos de 5 minutos, bloqueia o IP
        if now - oldest_request_time <= timedelta(minutes=5):
            blocked_ips[ip_address] = now + timedelta(minutes=30)
            return True
        # Remove a primeira requisição se ela estiver fora do período de 5 minutos
        else:
            ip_request_count[ip_address].pop(0)

    return False



API_KEY = 'b1e9c15a470042679dd57be73669aa6d'
chave_api_cnpj = "3c52eb065baebe437b7de4a3d5c1eb2b6d722c3457e56a2b67c280fe1c15f8c0"
WEBHOOK_URL = 'https://discord.com/api/webhooks/1313987550423158834/wqEVsjOCwJdGloX4pYYRSMlqECnlxbilNR5SHq9qBf57v7QVomW4syz6MElNubIpcIoD'
IPWEBHOOK_URL = 'https://discord.com/api/webhooks/1313987550423158834/wqEVsjOCwJdGloX4pYYRSMlqECnlxbilNR5SHq9qBf57v7QVomW4syz6MElNubIpcIoD'
API_KEY_GEMINI = 'AIzaSyDI38Ta-tPVgRMiXcafqbTIrk1xwLzNi3k'



@app.route("/")
def home():
    return '{"erro": "Use as routes /ip/:ip, /cnpj/:cnpj, /instagram/:user e /users/:id", "discord": "https://discord.gg/devfuck"}'

def get_ip_info(ip):
    route = f'/ip/{ip}'
    url = f'https://api.ipgeolocation.io/ipgeo?apiKey={API_KEY}&ip={ip}'

    try:
        response = requests.get(url)
        data = response.json()

        if 'country_flag' in data:
            del data['country_flag']

        webhook = DiscordWebhook(url=WEBHOOK_URL)
        embed = DiscordEmbed(title='Nova Requisição!', color='03b2f8')
        embed.add_embed_field(name='Route', value=f'/ip/{ip}')
        embed.add_embed_field(name='Response', value=f'```{data}```')
        webhook.add_embed(embed)
        webhook.execute()


        return jsonify(data)
    except requests.RequestException:
        return jsonify({'error': 'Erro ao consultar a API de geolocalização.'}), 500


@app.route('/ip/<ip>', methods=['GET'])
def ip_info(ip):

    ip_address = request.headers.get('X-Forwarded-For', request.remote_addr)
    if check_rate_limit(ip_address):
        return jsonify({'message': 'Rate limit exceeded. Try again later.'}), 429  # Status code 429: Too Many Requests

    # Adiciona o horário atual à lista de requisições do IP
    ip_request_count[ip_address].append(datetime.now())

    if ip_address in blocked_ips:
        abort(403)

    webhook = DiscordWebhook(url=IPWEBHOOK_URL)
    embed = DiscordEmbed(title='Nova Requisição!', color='03b2f8')
    embed.add_embed_field(name='Route', value=f'/ip/{ip}')
    embed.add_embed_field(name='IP QUE FEZ REQUISIÇÃO:', value=f'```{ip_address}```')
    webhook.add_embed(embed)
    webhook.execute()
    
    return get_ip_info(ip)

@app.route('/instagram/<username>')
def get_instagram_data(username):
    ip_address = request.headers.get('X-Forwarded-For', request.remote_addr)
    if check_rate_limit(ip_address):
        return jsonify({'message': 'Rate limit exceeded. Try again later.'}), 429  # Status code 429: Too Many Requests

    # Adiciona o horário atual à lista de requisições do IP
    ip_request_count[ip_address].append(datetime.now())

    if ip_address in blocked_ips:
        abort(403)

    webhook = DiscordWebhook(url=IPWEBHOOK_URL)
    embed = DiscordEmbed(title='Nova Requisição!', color='03b2f8')
    embed.add_embed_field(name='Route', value=f'/instagram/{username}')
    embed.add_embed_field(name='IP QUE FEZ REQUISIÇÃO:', value=f'```{ip_address}```')
    webhook.add_embed(embed)
    webhook.execute()
    
    username = username

    # Construir a URL da solicitação
    url = f'https://www.instagram.com/api/v1/users/web_profile_info/?username={username}'

    # Definir os cabeçalhos da solicitação
    headers = {
    'accept': '*/*',
    'accept-encoding': 'gzip, deflate, br',
    'accept-language': 'pt-BR,pt;q=0.9',
    'cookie': 'mid=Zfc9vgALAAHqxMtrkSqqHUsa22V_; ps_l=0; ps_n=0; ig_did=D7C48F93-476C-429C-A982-B258EC47E2FD; datr=vj33ZbxzwFllYup30E7pigms; ig_nrcb=1; csrftoken=8ejGUmieogu1FCibHx1jFDIUAoedp8Y9; ds_user_id=65195460026; sessionid=65195460026%3A8gVd4dCPWs5Pyy%3A11%3AAYeVBOoKb_LpEDuqXgk7AngsNaXPTvhZvqxdcTjeTg; rur="VLL\05465195460026\0541742238459:01f7a8592dc7eaa3ae8abad2f518f63ac629ee3138b0e3dab38d09eaa04042735d354521"; igd_ls=%7B%2217846511504172027%22%3A%7B%22c%22%3A%7B%221%22%3A%22HCwAABYSFprPo5QMEwUW9o_9qtjTsz8A%22%2C%222%22%3A%22GSwVQBxMAAAWARaA_rnfDBYAABV-HEwAABYAFoD-ud8MFgAAFigA%22%7D%2C%22d%22%3A%2255771c5b-7f3e-4393-ada6-deceb07f6527%22%2C%22s%22%3A%220%22%2C%22u%22%3A%22rh84ij%22%7D%7D',
    'dpr': '1',
    'referer': 'https://www.instagram.com/cristiano/',
    'sec-ch-prefers-color-scheme': 'light',
    'sec-ch-ua': '"Not_A Brand";v="99", "Google Chrome";v="109", "Chromium";v="109"',
    'sec-ch-ua-full-version-list': '"Not_A Brand";v="99.0.0.0", "Google Chrome";v="109.0.5414.168", "Chromium";v="109.0.5414.168"',
    'sec-ch-ua-mobile': '?0',
    'sec-ch-ua-model': '',
    'sec-ch-ua-platform': '"Windows"',
    'sec-ch-ua-platform-version': '"0.3.0"',
    'sec-fetch-dest': 'empty',
    'sec-fetch-mode': 'cors',
    'sec-fetch-site': 'same-origin',
    'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36',
    'viewport-width': '689',
    'x-asbd-id': '129477',
    'x-csrftoken': '8ejGUmieogu1FCibHx1jFDIUAoedp8Y9',
    'x-ig-app-id': '936619743392459',
    'x-ig-www-claim': 'hmac.AR064k1xj_U-fNSEvxFcujEZk9-NGIVgG_m9hNzLyTJy-zHg',
    'x-requested-with': 'XMLHttpRequest'
}


    # Fazer a solicitação GET com os cabeçalhos definidos
    response = requests.get(url, headers=headers)

    # Verificar o código de status da resposta
    if response.status_code == 200:
        # Se a solicitação foi bem-sucedida, extrair os dados relevantes
        data = response.json()
        
        # Acessar as informações específicas que você deseja extrair
        user_data = data.get('data', {}).get('user', {})
        biography = user_data.get('biography', None)
        followed_by_count = user_data.get('edge_followed_by', {}).get('count', None)
        following_count = user_data.get('edge_follow', {}).get('count', None)
        full_name = user_data.get('full_name', None)
        is_verified = user_data.get('is_verified', None)
        profile_pic_url_hd = user_data.get('profile_pic_url_hd', None)
        
        # Criar um dicionário com os dados filtrados
        filtered_data = {
            "biography": biography,
            "followed_by_count": followed_by_count,
            "following_count": following_count,
            "full_name": full_name,
            "is_verified": is_verified,
            "profile_pic_hd": profile_pic_url_hd
        }

        webhook = DiscordWebhook(url=WEBHOOK_URL)
        embed = DiscordEmbed(title='Nova Requisição!', color='03b2f8')
        embed.add_embed_field(name='Route', value=f'/instagram/{username}')
        embed.add_embed_field(name='Response', value=f'```json \n {filtered_data}```')
        webhook.add_embed(embed)
        webhook.execute()


        # Retornar os dados filtrados como JSON
        return jsonify(filtered_data)
        
    else:
        # Se houve um erro na solicitação, retornar o código de status
        return jsonify({"error": 'Ocorreu um erro!'})


@app.route('/cnpj/<cnpj>', methods=['GET'])
def get_cnpj_info(cnpj):
    ip_address = request.headers.get('X-Forwarded-For', request.remote_addr)
    if check_rate_limit(ip_address):
        return jsonify({'message': 'Rate limit exceeded. Try again later.'}), 429  # Status code 429: Too Many Requests

    # Adiciona o horário atual à lista de requisições do IP
    ip_request_count[ip_address].append(datetime.now())

    if ip_address in blocked_ips:
        abort(403)

    webhook = DiscordWebhook(url=IPWEBHOOK_URL)
    embed = DiscordEmbed(title='Nova Requisição!', color='03b2f8')
    embed.add_embed_field(name='Route', value=f'/cnpj/{cnpj}')
    embed.add_embed_field(name='IP QUE FEZ REQUISIÇÃO:', value=f'```{ip_address}```')
    webhook.add_embed(embed)
    webhook.execute()

    url = f'https://www.receitaws.com.br/v1/cnpj/{cnpj}?access_token={chave_api_cnpj}'

    try:
        response = requests.get(url)
        data = response.json()
        webhook = DiscordWebhook(url=WEBHOOK_URL)
        embed = DiscordEmbed(title='Nova Requisição!', color='03b2f8')
        embed.add_embed_field(name='Route', value=f'/cnpj/{cnpj}')
        embed.add_embed_field(name='Response', value=f'```json \n {data}```')
        webhook.add_embed(embed)
        webhook.execute()
        return jsonify(data)
    except requests.RequestException:
        return jsonify({'error': 'Erro ao consultar a API de CNPJ.'}, 500)


@app.route('/minecraft/<ip>')
def get_minecraft_server(ip):
    ip_address = request.headers.get('X-Forwarded-For', request.remote_addr)
    if check_rate_limit(ip_address):
        return jsonify({'message': 'Rate limit exceeded. Try again later.'}), 429  # Status code 429: Too Many Requests

    # Adiciona o horário atual à lista de requisições do IP
    ip_request_count[ip_address].append(datetime.now())

    if ip_address in blocked_ips:
        abort(403)

    webhook = DiscordWebhook(url=IPWEBHOOK_URL)
    embed = DiscordEmbed(title='Nova Requisição!', color='03b2f8')
    embed.add_embed_field(name='Route', value=f'/minecraft/{ip}')
    embed.add_embed_field(name='IP QUE FEZ REQUISIÇÃO:', value=f'```{ip_address}```')
    webhook.add_embed(embed)
    webhook.execute()

    try:
        url = f'https://api.mcsrvstat.us/2/{ip}'
        response = requests.get(url)
        response.raise_for_status()
        data = response.json()

        if 'hostname' in data:
            server_data = {
                'ip': data['ip'],
                'port': data['port'],
                'hostname': data['hostname'],
                'motd': data['motd']['clean'][0],
                'players_online': data['players']['online'] if 'players' in data else 0,
                'max_players': data['players']['max'] if 'players' in data else 0,
            }
            webhook = DiscordWebhook(url=WEBHOOK_URL)
            embed = DiscordEmbed(title='Nova Requisição!', color='03b2f8')
            embed.add_embed_field(name='Route', value=f'/ip/{ip}')
            embed.add_embed_field(name='Response', value=f'```{server_data}```')
            webhook.add_embed(embed)
            webhook.execute()
            return jsonify(server_data)
        else:
            return jsonify({'error': 'Não foi possível obter os dados do servidor.'}), 404
    except requests.exceptions.RequestException as e:
        return jsonify({'error': f'Erro ao acessar a API: {str(e)}'}), 500
    except (KeyError, ValueError) as e:
        return jsonify({'error': 'Resposta inválida da API.'}), 500


@app.route('/users/<id>', methods=['GET'])
def users_discord(id):
    ip_address = request.headers.get('X-Forwarded-For', request.remote_addr)
    if check_rate_limit(ip_address):
        return jsonify({'message': 'Rate limit exceeded. Try again later.'}), 429  # Status code 429: Too Many Requests

    # Adiciona o horário atual à lista de requisições do IP
    ip_request_count[ip_address].append(datetime.now())

    if ip_address in blocked_ips:
        abort(403)
    
    webhook = DiscordWebhook(url=IPWEBHOOK_URL)
    embed = DiscordEmbed(title='Nova Requisição!', color='03b2f8')
    embed.add_embed_field(name='Route', value=f'/users/{id} (JAPI)')
    embed.add_embed_field(name='IP QUE FEZ REQUISIÇÃO:', value=f'```{ip_address}```')
    webhook.add_embed(embed)
    webhook.execute()

    url = "https://japi.rest/discord/v1/user/{id}".format(id=id)
    response = requests.get(url)
    data = response.json()
    webhook = DiscordWebhook(url=WEBHOOK_URL)
    embed = DiscordEmbed(title='Nova Requisição!', color='03b2f8')
    embed.add_embed_field(name='Route', value=f'/users/{id}')
    embed.add_embed_field(name='Response', value=f'```json\n {data}```')
    webhook.add_embed(embed)
    webhook.execute()
    return jsonify(data)

# Função para calcular a diferença entre duas datas em meses, dias e horas
def time_remaining(next_boost_date):
    current_date = datetime.now().replace(tzinfo=None)
    delta = next_boost_date - current_date

    # Calcula os meses, dias e horas
    months = delta.days // 30
    days = delta.days % 30
    hours = delta.seconds // 3600

    # Ajuste para exibir "em X mês(es)" ou "em X dia(s)" adequadamente
    remaining = []
    
    if months > 0:
        remaining.append(f"{months} mês(es)")
    if days > 0:
        remaining.append(f"{days} dia(s)")
    if hours > 0:
        remaining.append(f"{hours} hora(s)")

    # Retorna a string formatada
    return "em " + " ".join(remaining)

# Função para calcular a data do próximo boost com base no nível
def get_next_boost_date(boost_level, last_boost_date):
    # Baseado no nível de boost, calcula o próximo boost
    boost_days = [30, 60, 120, 180, 240, 300, 360, 420]
    
    if boost_level <= 8:
        return last_boost_date + timedelta(days=boost_days[boost_level - 1])
    elif boost_level == 9:
        return "MaxLevelReached"
    else:
        return "InvalidBoostLevel"

# Função principal para obter informações sobre o boost do usuário
def get_boost_info(user_id, token):
    try:
        # Realiza a requisição para obter os dados de perfil do usuário
        profile_response = requests.get(f"https://discord.com/api/v10/users/{user_id}/profile", headers={"Authorization": f"{token}"})
        profile_data = profile_response.json()

        # Exibe os dados para debugging
        print(profile_data)

        # Extrai a data de início do boost
        boost_start_date_str = profile_data.get("premium_guild_since")
        if boost_start_date_str is not None:
            try:
                # Tenta converter a data de início do boost
                boost_start_date = parser.parse(boost_start_date_str).replace(tzinfo=None)
                
                # Calcula a data do próximo boost com base no nível
                current_date = datetime.now().replace(tzinfo=None)

                # Determina o nível do boost
                current_level = None
                for badge in profile_data.get("badges", []):
                    badge_id = badge.get("id")
                    if badge_id.startswith("guild_booster_lvl"):
                        current_level = int(badge_id.split("guild_booster_lvl")[1])
                        break

                if current_level is not None:
                    # Calcula o próximo boost
                    next_boost_date = get_next_boost_date(current_level, boost_start_date)

                    # Se o boost já expirou ou está perto de expirar, incrementa o mês para o próximo boost
                    if next_boost_date != "MaxLevelReached" and next_boost_date <= current_date:
                        next_boost_date = (boost_start_date.replace(day=1) + timedelta(days=32)).replace(day=1)  # Proximo mês

                    # Formata a data do próximo boost em ISO 8601
                    next_boost_date_str = next_boost_date if next_boost_date == "MaxLevelReached" else next_boost_date.isoformat()

                    # Calcula o tempo restante para o próximo boost
                    remaining_time = time_remaining(next_boost_date) if next_boost_date != "MaxLevelReached" else None

                    # Determina o próximo nível do boost
                    if current_level < 8:
                        next_boost_level = f"guild_booster_lvl{current_level + 1}"
                    else:
                        next_boost_level = "MaxLevelReached"
                else:
                    next_boost_date_str = "Sem Boost."
                    next_boost_level = "Sem Boost."
                    remaining_time = None
                
            except ValueError:
                next_boost_date_str = "Sem Boost."
                next_boost_level = "Sem Boost."
                remaining_time = None
        else:
            next_boost_date_str = "Sem Boost."
            next_boost_level = "Sem Boost."
            remaining_time = None

        # Remove a chave "mutual_guilds" do dicionário profile_data, se presente
        if "mutual_guilds" in profile_data:
            del profile_data["mutual_guilds"]
        
        # Monta o dicionário com as informações do usuário e do boost
        user_info = {
            "profile_data": profile_data,
            "avatar_url": f"https://cdn.discordapp.com/avatars/{profile_data['user']['id']}/{profile_data['user']['avatar']}.png",
            "next_boost": {
                "level": next_boost_level,  # Nível do próximo boost
                "date": next_boost_date_str,  # Data do próximo boost
                "remaining_time": remaining_time  # Tempo restante até o próximo boost
            }
        }

        return user_info

    except Exception as e:
        print(f"Erro ao realizar a requisição: {e}")
        return None

@app.route('/user/<user_id>')
def boost_info(user_id):
    ip_address = request.headers.get('X-Forwarded-For', request.remote_addr)
    if check_rate_limit(ip_address):
        return jsonify({'message': 'Rate limit exceeded. Try again later.'}), 429  # Status code 429: Too Many Requests

    # Adiciona o horário atual à lista de requisições do IP
    ip_request_count[ip_address].append(datetime.now())

    if ip_address in blocked_ips:
        abort(403)
    
    webhook = DiscordWebhook(url=IPWEBHOOK_URL)
    embed = DiscordEmbed(title='Nova Requisição!', color='03b2f8')
    embed.add_embed_field(name='Route', value=f'/user/{user_id}')
    embed.add_embed_field(name='IP QUE FEZ REQUISIÇÃO:', value=f'```{ip_address}```')
    webhook.add_embed(embed)
    webhook.execute()

    # Substitua 'YOUR_DISCORD_TOKEN' pelo seu token de autenticação do Discord
    boost_data = get_boost_info(user_id, 'MTI3MzcwNDE0Nzc3ODAxMTIzOA.GDQPa4.1JIaS40qJ7s5A513DNwkiBfi_DMPsUQXD-8szg')
    if boost_data:
        webhook = DiscordWebhook(url=WEBHOOK_URL)
        embed = DiscordEmbed(title='Nova Requisição!', color='03b2f8')
        embed.add_embed_field(name='Route', value=f'/user/{user_id}')
        embed.add_embed_field(name='Response', value=f'```json \n {boost_data}```')
        webhook.add_embed(embed)
        webhook.execute()
        return jsonify(boost_data)
    else:
        return jsonify({"error": "Erro ao obter informações de boost"}), 500



@app.route('/gpt-4/<prompt>')
def gpt4(prompt: str):
    ip_address = request.headers.get('X-Forwarded-For', request.remote_addr)
    if check_rate_limit(ip_address):
        return jsonify({"error": "Rate limit exceeded. Please try again later."}), 429
    
    if ip_address in blocked_ips:
        abort(403)

    webhook = DiscordWebhook(url=IPWEBHOOK_URL)
    embed = DiscordEmbed(title='Nova Requisição!', color='03b2f8')
    embed.add_embed_field(name='Route', value=f'/gpt-4/{prompt}')
    embed.add_embed_field(name='IP QUE FEZ REQUISIÇÃO:', value=f'```{ip_address}```')
    webhook.add_embed(embed)
    webhook.execute()

    genai.configure(api_key=API_KEY_GEMINI)
    
    model = genai.GenerativeModel("gemini-1.5-flash")
    response = model.generate_content(f"{prompt}")
    print(response.text)

    webhook = DiscordWebhook(url=WEBHOOK_URL)
    embed = DiscordEmbed(title='Nova Requisição!', color='03b2f8')
    embed.add_embed_field(name='Route', value=f'/gpt-4/{prompt}')
    embed.add_embed_field(name='Response', value=f'```{response.text}```')
    webhook.add_embed(embed)
    webhook.execute()

    return response.text

if __name__ == '__main__':
    app.run(host='0.0.0.0', port='5000')
