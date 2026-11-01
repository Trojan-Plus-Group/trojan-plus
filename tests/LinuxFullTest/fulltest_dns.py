'''
Local DNS fixtures and forwarding checks for Trojan Plus fulltest.
No system resolver or public DNS service is used.
'''
import socketserver
import tempfile
import threading
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

import dns.message
import dns.rcode
import dns.resolver
import dns.rrset
from fulltest_utils import print_time_log

DIRECT_DOMAIN = "direct.fulltest.test"
PROXY_DOMAIN = "proxy.fulltest.test"
DIRECT_MISSING = "missing.direct.fulltest.test"
PROXY_MISSING = "missing.proxy.fulltest.test"
ANSWERS = {DIRECT_DOMAIN: "192.0.2.10", PROXY_DOMAIN: "192.0.2.20"}


class DNSHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        data, sock = self.request
        try:
            query = dns.message.from_wire(data)
            response = dns.message.make_response(query)
            name = str(query.question[0].name).rstrip(".")
            if name in ANSWERS:
                response.answer.append(dns.rrset.from_text(name + ".", 60, "IN", "A", ANSWERS[name]))
            else:
                response.set_rcode(dns.rcode.NXDOMAIN)
            sock.sendto(response.to_wire(), self.client_address)
        except (dns.exception.DNSException, IndexError):
            return


@contextmanager
def local_fixture(port: int = 53) -> Iterator[tuple[int, str]]:
    with socketserver.UDPServer(("127.0.0.1", port), DNSHandler) as server:
        with tempfile.TemporaryDirectory(prefix="fulltest-dns-") as directory:
            gfwlist = Path(directory) / "gfwlist.txt"
            gfwlist.write_text(PROXY_DOMAIN + "\n", encoding="ascii")
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                yield server.server_address[1], str(gfwlist)
            finally:
                server.shutdown()
                thread.join()


def lookup_domain(domain: str, ns: str, count: int, port: int) -> bool:
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = [ns]
    resolver.port = port
    resolver.timeout = 2
    resolver.lifetime = 3
    expected = ANSWERS.get(domain)
    for _ in range(count):
        try:
            answers = resolver.resolve(domain, "A")
            actual = {str(answer) for answer in answers}
            if actual != {expected}:
                print_time_log(f"DNS mismatch for {domain}: expected {expected}, got {actual}")
                return False
        except dns.resolver.NXDOMAIN:
            if expected is not None:
                print_time_log(f"Unexpected NXDOMAIN for {domain}")
                return False
        except dns.exception.DNSException as error:
            print_time_log(f"DNS lookup failed for {domain}: {error}")
            return False
    return True


def start_query(ns: str, count: int, port: int) -> bool:
    print_time_log(f"start local DNS forwarding test @{ns}:{port}")
    with ThreadPoolExecutor(max_workers=3) as executor:
        tasks = [executor.submit(lookup_domain, domain, ns, count, port)
                 for domain in (DIRECT_DOMAIN, PROXY_DOMAIN, DIRECT_MISSING, PROXY_MISSING)]
        return all(task.result() for task in tasks)


if __name__ == "__main__":
    with local_fixture() as (port, _):
        assert start_query("127.0.0.1", 2, port)
