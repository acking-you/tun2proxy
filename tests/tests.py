import glob
import itertools
import os
import socket
import subprocess
import time
import unittest
import psutil

import dotenv
import requests

dotenv.load_dotenv()


def get_ip(version=None):
    """provider = 'https://%swtfismyip.com/text'
    prefix = {
        None: '',
        4: 'ipv4.',
        6: 'ipv6.'
    }[version]"""
    provider = 'https://%sipify.org'
    prefix = {
        None: 'api64.',
        4: 'api4.',
        6: 'api6.'
    }[version]
    result = requests.Session().get(provider % prefix, timeout=15).text.strip()
    return result


def get_tool_path():
    default = glob.glob(os.path.join(os.path.dirname(__file__), '..', 'target', '*', 'tun2proxy-bin'))
    default = default[0] if len(default) > 0 else 'tun2proxy-bin'
    return os.environ.get('TOOL_PATH', default)

def sudo_kill_process_and_children(proc):
    try:
        for child in psutil.Process(proc.pid).children(recursive=True):
            if child.name() == 'tun2proxy-bin':
                subprocess.run(['sudo', 'kill', str(child.pid)])
        subprocess.run(['sudo', 'kill', str(proc.pid)])
    except psutil.NoSuchProcess:
        pass

class Tun2ProxyTest(unittest.TestCase):
    @staticmethod
    def _test(ip_version, dns, proxy_var):
        proxy = os.getenv(proxy_var)
        if not proxy:
            raise unittest.SkipTest(f'{proxy_var} is not configured')
        if ip_version == 6:
            # Check route availability without sending a packet. An IPv6-only
            # external service cannot exercise a runner with no IPv6 route.
            try:
                with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as probe:
                    probe.connect(('2001:4860:4860::8888', 53))
            except OSError as error:
                raise unittest.SkipTest(f'runner has no IPv6 route: {error}') from error
        ip_noproxy = get_ip(ip_version)
        additional = ['-6'] if ip_version == 6 else []
        p = subprocess.Popen(
            ['sudo', get_tool_path(), "--proxy", proxy, '--setup', '-v', 'trace', '--dns', dns, *additional])
        try:
            time.sleep(1)
            ip_withproxy = get_ip(ip_version)

            assert ip_noproxy != ip_withproxy
        except Exception as e:
            raise e
        finally:
            sudo_kill_process_and_children(p)
            p.terminate()
            p.wait()

    @classmethod
    def add_tests(cls):
        ip_options = [None, 4]
        if bool(int(os.environ.get('IPV6', 1))):
            ip_options.append(6)
        for ip_version, dns, proxy_var in itertools.product(ip_options, ['virtual', 'over-tcp'],
                                                            ['SOCKS5_PROXY', 'HTTP_PROXY']):
            setattr(cls, 'test_ipv%s_dns%s_proxy%s' % (ip_version, dns, proxy_var),
                    lambda self, version=ip_version, mode=dns, proxy=proxy_var: cls._test(version, mode, proxy))


if __name__ == '__main__':
    Tun2ProxyTest.add_tests()
    unittest.main()
