import dns.resolver
import concurrent.futures
import ipaddress
from typing import List, Dict
import time


class blockchecker:
    def __init__(self):
        # List of DNS Blocklist services to check
        self.dnsbls = [
            'zen.spamhaus.org',
            'bl.spamcop.net',
            'cbl.abuseat.org',
            'b.barracudacentral.org',
            'dnsbl-1.uceprotect.net',
            'noptr.spamrats.com',
            'dnsbl-3.uceprotect.net',
            'dnsbl.dronebl.org'
        ]

        # DNS resolver
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 2
        self.resolver.lifetime = 2

    def reverse_ip(self, ip: str) -> str:
        """Reverse the IP address for Blocklist lookup capbility"""
        try:
            ipaddress.ip_address(ip)
            return '.'.join(reversed(ip.split('.')))
        except ValueError:
            raise ValueError(f"Invalid IP address: {ip}")

    def check_single_dnsbl(self, ip: str, dnsbl: str) -> Dict:
        """ Checks a single IP against a single DNSBL """
        reversed_ip = self.reverse_ip(ip)
        lookup = f"{reversed_ip}.{dnsbl}"
        result = {
            'dnsbl': dnsbl,
            'listed': False,
            'text': None,
            'error': None
        }

        try:
            answers = self.resolver.resolve(lookup, 'A')
            if answers:
                result['listed'] = True
                # Try to get TXT record for more information
                try:
                    txt = self.resolver.resolve(lookup, 'TXT')
                    result['text'] = [str(t) for t in txt][0]
                except:
                    pass
        except dns.resolver.NXDOMAIN:
            # Not listed
            pass
        except Exception as e:
            result['error'] = str(e)

        return result

    def check_ip(self, ip: str, max_workers: int = 10) -> Dict:
        """Check an IP against all DNSBLs in parallel."""
        results = []
        start_time = time.time()

        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_dnsbl = {
                executor.submit(self.check_single_dnsbl, ip, dnsbl): dnsbl
                for dnsbl in self.dnsbls
            }

            for future in concurrent.futures.as_completed(future_to_dnsbl):
                result = future.result()
                results.append(result)

        elapsed_time = time.time() - start_time
        return {
            'ip': ip,
            'elapsed_time': elapsed_time,
            'results': sorted(results, key=lambda x: x['dnsbl'])
        }

    def check_ip_list(self, ip_list: List[str]):
        total_ips = len(ip_list)
        print(f"\nProcessing {total_ips} IP addresses...")

        for index, ip in enumerate(ip_list, 1):
            try:
                print(f"\nChecking IP {index}/{total_ips}: {ip}")
                result = self.check_ip(ip.strip())
                self.print_results(result)
            except ValueError as e:
                print(f"Error with IP {ip}: {e}")
            except Exception as e:
                print(f"Unexpected error with IP {ip}: {e}")

    def print_results(self, results: Dict):
        print(f"\nResults for IP: {results['ip']}")
        print(f"Check completed in {results['elapsed_time']:.2f} seconds")
        print("-" * 60)

        listed_count = sum(1 for r in results['results'] if r['listed'])
        print(f"Listed on {listed_count} out of {len(self.dnsbls)} blacklists")
        print("-" * 60)

        for result in results['results']:
            status = "- LISTED" if result['listed'] else "+ not listed"
            print(f"{result['dnsbl']:<30} {status}")
            if result['text']:
                print(f"  → {result['text']}")
            if result['error']:
                print(f"  → Error: {result['error']}")


def clean_path(path: str) -> str:
    return path.strip().strip('"').strip("'").strip()


def read_ip_list(file_path: str) -> List[str]:
    file_path = clean_path(file_path)
    try:
        with open(file_path, 'r') as f:
            return [line.strip() for line in f
                    if line.strip() and not line.strip().startswith('#')]
    except FileNotFoundError:
        print(f"\nFile not found: {file_path}")
        print("Verify file path and try again.")
        return []
    except PermissionError:
        print(f"\nPermission denied when trying to access: {file_path}")
        print("Please check permission.")
        return []
    except Exception as e:
        print(f"\nFile cannot be read error: {e}")
        return []


def main():
    checker = blockchecker()
    while True:
        print("\n1. Check a single IP")
        print("2. Check many IPs from file")
        print("3. Quit")

        choice = input("\nPlease choose (1-3): ").strip()

        if choice == '1':
            try:
                ip = input("Enter single IP address to check: ").strip()
                results = checker.check_ip(ip)
                checker.print_results(results)
            except ValueError as e:
                print(f"Error: {e}")
            except Exception as e:
                print(f"An error occurred: {e}")

        elif choice == '2':
            file_path = input("Enter location of file with IP addresses: ")
            file_path = clean_path(file_path)

            if not file_path:
                print("No file path provided!")
                continue

            try:
                ip_list = read_ip_list(file_path)
                if not ip_list:
                    print("No valid IP addresses found in file!")
                    continue

                checker.check_ip_list(ip_list)

            except Exception as e:
                print(f"An error occurred: {e}")
                print("Tips:")
                print("- Make sure the file exists")
                print("- Check if the path is correct")
                print("- Ensure you have permission to read the file")

        elif choice == '3':
            break

        else:
            print("Invalid choice!")


if __name__ == "__main__":
    main()
