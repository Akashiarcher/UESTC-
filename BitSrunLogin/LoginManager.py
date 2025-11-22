import base64
import requests
import re
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from ._decorators import *

from .encryption.srun_md5 import *
from .encryption.srun_sha1 import *
from .encryption.srun_base64 import *
from .encryption.srun_xencode import *

header = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) '
                  'Chrome/63.0.3239.26 Safari/537.36'
}


class LoginManager:

    @staticmethod
    def encode(s):
        return base64.b64encode(s.encode()).decode()

    @staticmethod
    def decode(s):
        return base64.b64decode(s).decode()

    def __init__(self, **kwargs):
        # 所有配置集中在 self.args 里
        self.args = {
            # 基础 URL：主机即可，不带路径
            'url': 'http://10.253.0.235',  # 会被 config.py 里的 url 覆盖

            # 相对路径（后面根据 base url 拼）
            'url_login_page': "/srun_portal_pc",        # 登录页 path
            'url_get_challenge_api': "/cgi-bin/get_challenge",
            'url_login_api': "/cgi-bin/srun_portal",

            # 认证参数
            'n': "200",
            'vtype': "1",
            'ac_id': "3",         # 主楼=1，宿舍=3
            'enc': "srun_bx1",
            'domain': "@dx",      # 会被 config 里的 domain 覆盖

            # 临时参数
            'username': None,
            'password': None,
            'ip': None,
        }

        # 用户名/密码/IP 等直观属性
        self.username = None
        self.password = None
        self.ip = None

        # 覆盖配置（包括 config.py 中的 url / ac_id / domain）
        self.args.update(kwargs)

        # 基础 host（去掉 query 和结尾 /）
        base = self.args['url'].split('?')[0].rstrip('/')
        ac_id = str(self.args.get('ac_id', '3'))

        # 登录页使用和浏览器一致的地址：/srun_portal_pc?ac_id=3&theme=pro
        self.args['url_login_page'] = f"{base}/srun_portal_pc?ac_id={ac_id}&theme=pro"
        self.args['url_get_challenge_api'] = f"{base}{self.args['url_get_challenge_api']}"
        self.args['url_login_api'] = f"{base}{self.args['url_login_api']}"

        # 会话对象：用它来保持 cookie
        self.session = requests.Session()
        # 默认头
        self.session.headers.update(header)

    def login(self, username, password, decode=False):
        if decode:
            username = LoginManager.decode(username)
            password = LoginManager.decode(password)

        # 拼接运营商后缀
        self.username = str(username) + self.args['domain']
        self.password = str(password)

        self.get_ip()
        self.get_token()
        self.get_login_responce()

    def get_ip(self):
        print("Step1: Get local ip returned from srun server.")
        self._get_login_page()
        self._resolve_ip_from_login_page()
        print("----------------")

    def get_token(self):
        """
        Step2: 获取 challenge / token
        """
        print("Step2: Get token by resolving challenge result.")
        # 用已有的 _get_challenge + _resolve_token_from_challenge_response
        self._get_challenge()
        self._resolve_token_from_challenge_response()

    def get_login_responce(self):
        print("Step3: Loggin and resolve response.")
        self._generate_encrypted_login_info()
        self._send_login_info()
        self._resolve_login_responce()
        print("The loggin result is: " + self._login_result)
        print("----------------")

    def _is_defined(self, varname):
        """
        Check whether variable is defined in the object
        """
        allvars = vars(self)
        return varname in allvars

    @infomanage(
        callinfo="Getting login page",
        successinfo="Successfully get login page",
        errorinfo="Failed to get login page, maybe the login page url is not correct"
    )
    def _get_login_page(self):
        # Step1: Get login page（使用 session，以便保存 cookie）
        self._page_response = self.session.get(
            self.args['url_login_page'],
            # 校园网是 http，这里 verify 无所谓；如果将来换 https 可以用 verify=False
        )

    @checkvars(
        varlist="_page_response",
        errorinfo="Lack of login page html. Need to run '_get_login_page' in advance to get it"
    )
    @infomanage(
        callinfo="Resolving IP from login page html",
        successinfo="Successfully resolve IP",
        errorinfo="Failed to resolve IP"
    )
    def _resolve_ip_from_login_page(self):
        """
        从登录页 HTML / JS 中解析 IP，并顺便解析 ServiceIP（仅打印，不改接口地址）
        """
        text = self._page_response.text
        """
# ===== 临时调试，把登录页 HTML 打出来看看 =====
        print("===== login page raw html (first 1000 chars) =====")
        print(text[:1000])
        print("===================================================")
        # ===============================================
        """
        ip = None

        # 兼容旧版本 hidden input 写法
        patterns = [
            r'id=["\']user_ip["\']\s+value=["\'](.*?)["\']',
            r'id=["\']online_ip["\']\s+value=["\'](.*?)["\']',
            r'id=["\']v46ip["\']\s+value=["\'](.*?)["\']',
        ]
        for pat in patterns:
            m = re.search(pat, text)
            if m:
                ip = m.group(1)
                break

        # 现版本：CONFIG 里  ip     : "10.20.1.141"
        if ip is None:
            m = re.search(r'\bip\s*:\s*"([^"]+)"', text)
            if m:
                ip = m.group(1)

        if ip is None:
            # 解析不到直接报错
            # print(text[:1000])  # 调试时可打开
            raise ValueError("Cannot resolve IP from login page")

        self.ip = ip
        print("Successfully resolve IP, ip =", self.ip)

        # 从 CONFIG 里解析 ServiceIP，仅记录/打印，不再覆盖接口地址
        m_srv = re.search(r'"ServiceIP"\s*:\s*"([^"]+)"', text)
        if m_srv:
            self.service_ip = m_srv.group(1).rstrip('/')
            print("Resolve ServiceIP =", self.service_ip)
        else:
            self.service_ip = None
            print("ServiceIP not found in CONFIG")

    @checkip
    @infomanage(
        callinfo="Begin getting challenge",
        successinfo="Challenge response successfully received",
        errorinfo="Failed to get challenge response, maybe the url_get_challenge_api is not correct. "
                  "Else check params_get_challenge"
    )
    def _get_challenge(self):
        """
        按 HAR 抓到的方式请求 /cgi-bin/get_challenge
        GET http://10.253.0.235/cgi-bin/get_challenge
            ?callback=jQuery1102...
            &username=<REMOVED>@cmcc
            &ip=10.20.1.141
            &_=timestamp
        """
        import time

        ts = int(time.time() * 1000)
        callback = f"jQuery{ts}"

        params_get_challenge = {
            "callback": callback,
            "username": self.username,  # 已经是 "学号@cmcc"
            "ip": self.ip,
            "_": str(ts),
        }

        # 参考 HAR 设置部分 header（尤其是 Referer / X-Requested-With / Accept）
        ch_headers = header.copy()
        ch_headers.update({
            "Referer": self.args['url_login_page'],
            "X-Requested-With": "XMLHttpRequest",
            "Accept": "text/javascript, application/javascript, application/ecmascript, application/x-ecmascript, */*; q=0.01",
        })

        url = self.args['url_get_challenge_api']

        self._challenge_response = self.session.get(
            url,
            params=params_get_challenge,
            headers=ch_headers,
            # 校园网是 http，verify 不影响；若将来改为 https，有证书问题可加 verify=False
        )

    @checkvars(
        varlist="_challenge_response",
        errorinfo="Lack of challenge response. Need to run '_get_challenge' in advance"
    )
    @infomanage(
        callinfo="Resolving token from challenge response",
        successinfo="Successfully resolve token",
        errorinfo="Failed to resolve token"
    )
    def _resolve_token_from_challenge_response(self):
        text = self._challenge_response.text

        # 一般 srun 返回的 JSON/JSONP 里会有 "challenge":"xxxx"
        m = re.search(r'"challenge"\s*:\s*"([^"]+)"', text)
        if not m:
            raise ValueError("Cannot resolve token from challenge response")

        self.token = m.group(1)

    @checkip
    def _generate_info(self):
        info_params = {
            "username": self.username,
            "password": self.password,
            "ip": self.ip,
            "acid": self.args['ac_id'],
            "enc_ver": self.args['enc']
        }
        info = re.sub("'", '"', str(info_params))
        self.info = re.sub(" ", '', info)

    @checkinfo
    @checktoken
    def _encrypt_info(self):
        self.encrypted_info = "{SRBX1}" + get_base64(get_xencode(self.info, self.token))

    @checktoken
    def _generate_md5(self):
        self.md5 = get_md5(self.password, self.token)

    @checkmd5
    def _encrypt_md5(self):
        self.encrypted_md5 = "{MD5}" + self.md5

    @checktoken
    @checkip
    @checkencryptedinfo
    def _generate_chksum(self):
        self.chkstr = self.token + self.username
        self.chkstr += self.token + self.md5
        self.chkstr += self.token + self.args['ac_id']
        self.chkstr += self.token + self.ip
        self.chkstr += self.token + self.args['n']
        self.chkstr += self.token + self.args['vtype']
        self.chkstr += self.token + self.encrypted_info

    @checkchkstr
    def _encrypt_chksum(self):
        self.encrypted_chkstr = get_sha1(self.chkstr)

    def _generate_encrypted_login_info(self):
        self._generate_info()
        self._encrypt_info()
        self._generate_md5()
        self._encrypt_md5()

        self._generate_chksum()
        self.password = "{MD5}" + self.md5
        self._encrypt_chksum()

    @checkip
    @checkencryptedmd5
    @checkencryptedinfo
    @checkencryptedchkstr
    @infomanage(
        callinfo="Begin to send login info",
        successinfo="Login info send successfully",
        errorinfo="Failed to send login info"
    )
    def _send_login_info(self):
        login_info_params = {
            'callback': 'jQuery112407481914773997063_1631531125398',  # 可任意字符串，但不能缺
            'action': 'login',
            'username': self.username,
            'password': self.encrypted_md5,
            'ac_id': self.args['ac_id'],
            'ip': self.ip,
            'chksum': self.encrypted_chkstr,
            'info': self.encrypted_info,
            'n': self.args['n'],
            'type': self.args['vtype'],
            'os': "Windows 10",
            'name': "Windows",
            'double_stack': 0
        }
        self._login_responce = requests.get(
            self.args['url_login_api'],
            params=login_info_params,
            headers=header,
            verify=False,
        )

    @checkvars(
        varlist="_login_responce",
        errorinfo="Need _login_responce. Run _send_login_info in advance"
    )
    @infomanage(
        callinfo="Resolving login result",
        successinfo="Login result successfully resolved",
        errorinfo="Cannot resolve login result. Maybe the srun response format is changed"
    )
    def _resolve_login_responce(self):
        self._login_result = re.search('"error":"(.*?)"', self._login_responce.text).group(1)


if __name__ == '__mian__':
    m = LoginManager()
