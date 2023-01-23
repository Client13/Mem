import requests,os
#os.system("pip install tls_client")
import tls_client
import json
import base64
import requests
import time

from hcapbypass import bypass

__useragent__ = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36"#requests.get('https://discord-user-api.cf/api/v1/properties/web').json()['chrome_user_agent']
build_number = 165485#int(requests.get('https://discord-user-api.cf/api/v1/properties/web').json()['client_build_number'])
cv = "108.0.0.0"
__properties__ = base64.b64encode(json.dumps({"os": "Windows","browser": "Chrome","device": "PC","system_locale": "en-GB","browser_user_agent": __useragent__,"browser_version": cv,"os_version": "7","referrer": "","referring_domain": "","referrer_current": "","referring_domain_current": "","release_channel": "stable","client_build_number": build_number,"client_event_source": None}, separators=(',', ':')).encode()).decode()

def get_headers(token, url):
  headers = {
    "Authorization": token,
    "Origin": "https://discord.com",
    "Accept": "*/*",
    "X-Discord-Locale": "en-GB",
    "X-Super-Properties": __properties__,
    "User-Agent": __useragent__,
    "Referer": url,
    "X-Debug-Options": "bugReporterEnabled",
    "Content-Type": "application/json"
  }
  return headers

def authorize(urlauth,url,token,captcha,guild):
  data = {"authorize": True, "permissions": 0, "guild_id": guild, "captcha_service": "hcaptcha", "captcha_key": captcha}
  client = tls_client.Session(client_identifier="firefox_102")
  client.headers.update(get_headers(token,url))
  r1 = client.get(url)
  r2 = client.get(urlauth)
  r3 = client.post(urlauth, json=data)
  print(r3.text)

def check_ifnotin(id,sv):
  r = requests.get(f"https://discord.com/api/v9/guilds/{sv}/members/{id}", headers={"Authorization": token})
  try:
    ok = r.json()
  except:
    print("Rate Limited")
    os.system("kill 1")
  try:
    ok["avatar"]
  except:
    return True
  return False




def get_captcha():
  print("Getting Captcha Key......")
  
# python requests
  import requests
  balance = requests.get('https://free.nocaptchaai.com/balance', headers={'apikey': 'runx-1bd977ff-0f83-cb51-18ab-f87e73480c36'})

  print(balance.json())

  #capres = requests.get("https://Capsolverv2.notauth1337.repl.co/solve", json={"sitekey": "f5561ba9-8f1e-40ca-9b5b-a0b3f719ef34", "site": "https://discord.com/api/oauth2/authorize", "key": "1"}, headers={"Authorization": "HelloImUnderTheWater!"})
 #, "Content-type": "application/json",
  # })
  sitekey="f5561ba9-8f1e-40ca-9b5b-a0b3f719ef34"
  url="https://discord.com/api/oauth2/authorize"
  capres= bypass(sitekey, url, proxy="172.104.162.209:9999")
  print(capres)
  capkey = capres.json()
  print(capkey)
  return capkey

bot_ids = [1033059459968270427]
server_ids = [1061900489651916870]
token = os.getenv("tkn")
delay = 5


def generate_url(id, auth):
  if auth:
    url = f"https://discord.com/api/v10/oauth2/authorize?client_id={id}&permissions=0&scope=bot"
  else:
    url = f"https://discord.com/oauth2/authorize?client_id={id}&permissions=0&scope=bot"
  return url


def main():
  print("Bot Adder By Auth#1337")
  for server in server_ids:
    for bot in bot_ids:
      url1 = generate_url(bot, False)
      url2 = generate_url(bot,True)
      print(f"Authorizing Bot {bot} To Server {server}")
      if check_ifnotin(bot,server):
        captcha = get_captcha()
        #captcha=None
        authorize(url2,url1,token,captcha,server)
        print(f"Authorized Bot {bot} To Server {server}")
        print(f"Sleeping {delay} Seconds")
        time.sleep(delay)
      else:
        print("already bot in sv")


if __name__ == "__main__":
  main()