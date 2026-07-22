import json
import os
import subprocess
import unittest


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class RustCoreProtocolTest(unittest.TestCase):
    def test_filter_package_urls_returns_metadata(self):
        candidates = [
            os.path.join(ROOT, 'target', 'debug', 'libc_tool_core'),
            os.path.join(ROOT, 'target', 'release', 'libc_tool_core'),
        ]
        core_path = next((path for path in candidates if os.path.isfile(path)), None)
        if not core_path:
            self.skipTest('Rust core is not built')
        control = (
            'Package: libc6\n'
            'Architecture: amd64\n'
            'Version: 2.31-0ubuntu9\n'
            'Filename: pool/main/g/glibc/libc6_2.31-0ubuntu9_amd64.deb\n'
            'Size: 42\n'
            'SHA256: deadbeef\n\n'
        )
        result = subprocess.run(
            [core_path, 'filter-package-urls', 'https://archive.test/ubuntu', 'amd64', 'libc6', '', ''],
            input=control,
            text=True,
            capture_output=True,
            check=True,
        )
        metadata = json.loads(result.stdout.strip())
        self.assertEqual(metadata['package_url'], 'https://archive.test/ubuntu/pool/main/g/glibc/libc6_2.31-0ubuntu9_amd64.deb')
        self.assertEqual(metadata['package_sha256'], 'deadbeef')
        self.assertEqual(metadata['package_size'], '42')


if __name__ == '__main__':
    unittest.main()
