import re
from openai import OpenAI

# ✅ 1. OpenAI API 키 설정
client = OpenAI(api_key="api 키 입력칸")

# ✅ 2. 로그 마스커 클래스
class LogMasker:
    def __init__(self):
        self.ip_map = {}
        self.user_map = {}
        self.email_map = {}
        self.host_map = {}
        self.counter = {'ip': 1, 'user': 1, 'email': 1, 'host': 1}

    def mask(self, line):
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        line = self._mask_with_map(line, ip_pattern, self.ip_map, 'IP')

        user_pattern = r'\b(?:admin|root|user\d*|guest)\b'
        line = self._mask_with_map(line, user_pattern, self.user_map, 'USER')

        # ✅ URL 파라미터 민감 정보 먼저 마스킹
        line = re.sub(r'([?&](token|pass|code|secret)=)[^&\s]+', r'\1MASKED_PARAM', line, flags=re.IGNORECASE)

        line = re.sub(r'(token|session|auth|api[_-]?key)=\w+', r'\1=MASKED_TOKEN', line, flags=re.IGNORECASE)

        email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b'
        line = self._mask_with_map(line, email_pattern, self.email_map, 'EMAIL')

        line = re.sub(r'\b01[0-9]-\d{3,4}-\d{4}\b', 'MASKED_PHONE', line)

        # ✅ 경로 마스킹은 마지막
        line = re.sub(r'(\/[\w\.-]+)+', '/MASKED_PATH', line)

        host_pattern = r'\b[a-zA-Z0-9.-]+\.(local|internal|corp|lan)\b'
        line = self._mask_with_map(line, host_pattern, self.host_map, 'HOST')

        return line

    def _mask_with_map(self, text, pattern, value_map, label):
        matches = re.findall(pattern, text)
        for val in matches:
            if val not in value_map:
                tag = f'{label}_{self.counter[label.lower()]}'
                value_map[val] = tag
                self.counter[label.lower()] += 1
            text = text.replace(val, value_map[val])
        return text

# ✅ 3. 프롬프트 구성
def make_prompt_from_logs(log_lines):
    return (
        "다음은 웹서버 보안 로그입니다.\n"
        "각 로그의 의심스러운 행동 여부를 판단하고, 그 이유를 간단히 설명해 주세요.\n\n"
        + "\n".join(log_lines)
    )

# ✅ 4. GPT에게 요청
def ask_gpt(prompt):
    response = client.chat.completions.create(
        model="gpt-3.5-turbo", 
        messages=[
            {"role": "system", "content": "당신은 사이버 보안 분석가입니다."},
            {"role": "user", "content": prompt}
        ],
        temperature=0.3,
        max_tokens=1000
    )
    return response.choices[0].message.content

# ✅ 5. 로그 전체 처리
def analyze_log_file(file_path):
    masker = LogMasker()
    with open(file_path, 'r') as f:
        lines = [line.strip() for line in f if line.strip()]
    
    masked_logs = [masker.mask(line) for line in lines]
    prompt = make_prompt_from_logs(masked_logs[:30])  # 너무 길면 자르기
    result = ask_gpt(prompt)

    print("\n🔍 [GPT 로그 분석 결과] 🔍\n")
    print(result)

# ✅ 6. 실행
if __name__ == "__main__":
    input_log = "sample.log"  # ← 분석할 로그 파일명
    analyze_log_file(input_log)
