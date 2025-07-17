import base64
import hashlib
import json
import os
import re

import openai
import requests
from dotenv import load_dotenv
from flask import Flask, request, jsonify

app = Flask(__name__)

# Load environment variables
load_dotenv()

OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
ALIENVAULT_API_KEY = os.getenv("ALIENVAULT_API_KEY")

# Init client OpenAI
client = openai.Client()

# Analyze query to determine type and value
def parse_query(query):
    try:
        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {
                    "role": "system",
                    "content": """Bạn là một AI chuyên phân tích cảnh báo an toàn thông tin. Nhiệm vụ của bạn là phân tích query và xác định loại dữ liệu (url, ip, hash, hoặc process) cùng giá trị tương ứng. Trả về kết quả dưới dạng JSON với các trường:
                    - "type": Loại dữ liệu ("url", "ip", "hash", "process", hoặc "unknown").
                    - "value": Giá trị tương ứng (URL, địa chỉ IP, hash, hoặc đường dẫn/tên file).
                    Nếu không xác định được, trả về {"type": "unknown", "value": null}.
                    Ví dụ:
                    - Query: "Kiểm tra URL https://viettelstore.vn/" -> {"type": "url", "value": "https://viettelstore.vn/"}
                    - Query: "Kiểm tra IP 192.168.1.1" -> {"type": "ip", "value": "192.168.1.1"}
                    - Query: "File npkpdb.dll có hash 178ba564b39bd07577e974a9b677dfd86ffa1f1d0299dfd958eb883c5ef6c3e1" -> {"type": "hash", "value": "178ba564b39bd07577e974a9b677dfd86ffa1f1d0299dfd958eb883c5ef6c3e1"}
                    - Query: ''"C:\\windows\\SysWOW64\\schtasks.exe có độc hại không ?" -> {"type": "process", "value": "C:\\windows\\SysWOW64\\schtasks.exe"}
                    """
                },
                {"role": "user", "content": f"Query: {query}"}
            ],
            response_format={"type": "json_object"}
        )
        result = response.choices[0].message.content
        parsed = json.loads(result)
        # print(f"parsed LLM result: {parsed}")
        return parsed.get("type", "unknown"), parsed.get("value", None)
    except Exception as e:
        print(f"Error parsing query with LLM: {str(e)}")
        return "unknown", None


# calculate hash SHA256 file
def calculate_file_hash(file_path):
    try:
        sha256 = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256.update(chunk)
        return sha256.hexdigest()
    except FileNotFoundError:
        print(f"File not found: {file_path}")
        return None
    except Exception as e:
        print(f"Error calculating hash: {str(e)}")
        return None


# VirusTotal
def check_virustotal(item_type, value):
    if not value or item_type == "unknown":
        return "unknown"

    headers = {"x-apikey": VIRUSTOTAL_API_KEY}

    if item_type == "url":
        encoded_url = base64.urlsafe_b64encode(value.encode()).decode().rstrip("=")
        url = f"https://www.virustotal.com/api/v3/urls/{encoded_url}"
        response = requests.get(url, headers=headers)
        # print(f"VirusTotal response for URL: {response.status_code}, {response.text}")
    elif item_type == "ip":
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{value}"
        response = requests.get(url, headers=headers)
        # print(f"VirusTotal response for IP: {response.status_code}, {response.text}")
    elif item_type == "hash":
        url = f"https://www.virustotal.com/api/v3/files/{value}"
        response = requests.get(url, headers=headers)
        # print(f"VirusTotal response for hash: {response.status_code}, {response.text}")
    elif item_type == "process":
        hash_value = calculate_file_hash(value)
        if hash_value:
            url = f"https://www.virustotal.com/api/v3/files/{hash_value}"
            response = requests.get(url, headers=headers)
            # print(f"VirusTotal response for process hash: {response.status_code}, {response.text}")
        else:
            return "unknown"
    else:
        return "unknown"

    if response.status_code == 200:
        result = response.json().get("data", {}).get("attributes", {}).get("last_analysis_stats")
        # print(f"VirusTotal result: {result}")
        if result and result.get("malicious", 0) > 0:
            return "malicious"
        return "clean"
    return "unknown"

# AlienVault OTX
def check_alienvault(item_type, value):
    if item_type not in ["url", "ip", "hash"]:
        return "unknown"
    if item_type == "url":
        value = re.sub(r"^https?://", "", value).rstrip("/")
    url = f"https://otx.alienvault.com/api/v1/indicators/{'domain' if item_type == 'url' else item_type}/{value}"
    headers = {"X-OTX-API-KEY": ALIENVAULT_API_KEY}
    response = requests.get(url, headers=headers)
    # print(f"AlienVault response: {response.status_code}, {response.text}")
    if response.status_code == 200:
        result = response.json()
        # print(f"AlienVault result: {result}")
        if result.get("pulse_info", {}).get("count", 0) > 0:
            return "malicious"
        return "clean"
    return "unknown"


# Route for the root path
@app.route('/', methods=['GET'])
def home():
    return jsonify({
        "message": "Welcome",
        "endpoints": {
            "/analysis_agent": "POST - Analyze to detect abnormalities in security alerts. Send JSON with 'query' field.",
        }
    })


@app.route('/analysis_agent', methods=['POST'])
def analysis_agent():
    try:
        data = request.json
        query = data.get('query')
        query = query.replace('\\', '\\\\')
        query = re.sub(r'\s+', ' ', query.strip())

        # Analyze query to determine type and value
        item_type, value = parse_query(query)
        if not value:
            return jsonify({"error": f"Could not parse query: {query}"}), 400

        # Result check with VirusTotal and AlienVault
        vt_result = check_virustotal(item_type, value)
        av_result = check_alienvault(item_type, value)

        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system",
                 "content": """Bạn là một AI chuyên phân tích cảnh báo an toàn thông tin. Hãy phân tích thông tin sau để đưa ra nhận định và trả về kết quả chính xác nhất. Kêt quả sẽ trả về dưới dạng JSON với các trường: 
                    - "analysis": Mô tả chi tiết nhận định của bạn, xem xét cả loại dữ liệu, giá trị, và kết quả từ VirusTotal/AlienVault. Nếu phát hiện dấu hiệu đáng ngờ (như typosquatting, thư mục không chuẩn, hoặc kết quả "malicious"), giải thích rõ ràng.
                    - "result": Kết quả tổng hợp ("ABNORMAL", "CLEAN", hoặc "UNKNOWN"). Nếu VirusTotal hoặc AlienVault báo "malicious", kết quả phải là "ABNORMAL". Nếu cả hai báo "clean" nhưng có dấu hiệu đáng ngờ (như typosquatting hoặc thư mục không chuẩn), kết quả vẫn có thể là "ABNORMAL". Nếu không đủ thông tin, trả về "UNKNOWN".
                 """},
                {"role": "user", "content": f"Loại: {item_type}, Giá trị: {value}, Kết quả VirusTotal: {vt_result}, Kết quả AlienVault: {av_result}"}
            ],
            response_format={"type": "json_object"}
        )

        result = json.loads(response.choices[0].message.content)
        return jsonify(result)

    except Exception as e:
        print(f"error: {str(e)}")
        return jsonify({"error": str(e)}), 500


if __name__ == '__main__':
    app.run(host='localhost', port=8989)
