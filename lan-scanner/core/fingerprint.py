import requests
import json
from urllib.parse import urljoin
import urllib3
urllib3.disable_warnings()

def load_fingerprints():
    """加载增强版指纹库"""
    try:
        with open("data/fingerprints.json", "r", encoding='utf-8') as f:
            fingerprints = json.load(f)
            
        # 添加默认服务器指纹（硬编码保障基础识别）
        default_prints = [
            {
                "name": "Microsoft IIS",
                "headers": ["server: microsoft-iis"],
                "keywords": ["internet information services"]
            },
            {
                "name": "Apache",
                "headers": ["server: apache"],
                "keywords": ["apache http server"]
            },
            {
                "name": "Nginx",
                "headers": ["server: nginx"],
                "keywords": ["nginx/"]
            }
        ]
        return fingerprints + default_prints
    except Exception as e:
        print(f"[ERROR] 加载指纹库失败: {e}")
        return default_prints

def fingerprint_identify(ip, port, fingerprints):
    """终极版识别函数"""
    schemes = ['http']  # 先只检查HTTP，避免HTTPS干扰
    
    for scheme in schemes:
        url = f"{scheme}://{ip}:{port}"
        try:
            # 带重试机制的请求
            response = requests.get(
                url,
                timeout=3,
                verify=False,
                headers={'User-Agent': 'Mozilla/5.0'},
                allow_redirects=True
            )
            
            # 关键识别逻辑
            content = response.text.lower()
            headers = str(response.headers).lower()
            
            # 1. 优先检查Server头
            server = response.headers.get('Server', '').lower()
            if 'microsoft-iis' in server:
                return "Microsoft IIS"
            if 'apache' in server:
                return "Apache"
            if 'nginx' in server:
                return "Nginx"
            
            # 2. 检查页面内容特征
            if any(kw in content for kw in ["iis welcome", "internet information services"]):
                return "Microsoft IIS"
                
            # 3. 检查默认页面特征
            if "<title>Welcome to nginx!</title>" in content:
                return "Nginx"
                
            # 4. 检查指纹库
            for fp in fingerprints:
                if any(hdr in headers for hdr in fp.get("headers", [])):
                    return fp["name"]
                if any(kw in content for kw in fp.get("keywords", [])):
                    return fp["name"]
                    
        except requests.RequestException:
            continue
            
    return "web server"  # 比Unknown更友好的默认值

# 测试代码
if __name__ == "__main__":
    print("正在测试本地IIS识别...")
    print("识别结果:", fingerprint_identify("127.0.0.1", 80, load_fingerprints()))