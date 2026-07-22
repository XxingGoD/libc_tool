import hashlib
import io
import json
import os
import tarfile
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

import libc_tool


class LibcToolTest(unittest.TestCase):
    def test_debian_control_parser_preserves_continuations(self):
        entries = list(libc_tool.iter_debian_control_entries(
            "Package: libc6\n"
            "Architecture: amd64\n"
            "Description: short\n"
            " long description\n"
            "\n"
        ))
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]['Package'], 'libc6')
        self.assertEqual(entries[0]['Description'], 'short\nlong description')

    def test_package_metadata_and_url_normalization(self):
        metadata = libc_tool.package_metadata_from_control_entry(
            {
                'Package': 'libc6',
                'Version': '2.31-0ubuntu9',
                'Architecture': 'amd64',
                'Filename': 'pool/main/g/glibc/libc6_2.31-0ubuntu9_amd64.deb',
                'Size': '123',
                'SHA256': 'ABCD',
            },
            'https://archive.ubuntu.com//ubuntu',
            distro='ubuntu',
            release='20.04',
        )
        self.assertEqual(
            metadata['package_url'],
            'https://archive.ubuntu.com/ubuntu/pool/main/g/glibc/libc6_2.31-0ubuntu9_amd64.deb',
        )
        self.assertEqual(metadata['package_size'], 123)
        self.assertEqual(metadata['package_sha256'], 'abcd')

    def test_index_schema_requires_package_url_field(self):
        index = {
            'schema_version': libc_tool.CACHE_SCHEMA_VERSION,
            'by_id': {},
            'by_arch': {},
            'by_build_id': {},
            'by_build_id_prefix': {},
            'by_sha1': {},
            'by_version': {},
            'by_version_arch': {},
            'by_symbol_suffix': {},
            'versions_sorted': [],
            'entries': [{'id': 'a', 'package_url': None}],
        }
        self.assertTrue(libc_tool.index_cache_is_compatible(index))
        index['entries'][0].pop('package_url')
        self.assertFalse(libc_tool.index_cache_is_compatible(index))

    def test_safe_extract_rejects_path_traversal_and_devices(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            archive = io.BytesIO()
            with tarfile.open(fileobj=archive, mode='w') as tar_obj:
                member = tarfile.TarInfo('../outside')
                member.size = 0
                tar_obj.addfile(member)
            archive.seek(0)
            with tarfile.open(fileobj=archive, mode='r:') as tar_obj:
                with self.assertRaises(ValueError):
                    libc_tool.safe_extract_tar(tar_obj, temp_dir)

            archive = io.BytesIO()
            with tarfile.open(fileobj=archive, mode='w') as tar_obj:
                member = tarfile.TarInfo('dev/null')
                member.type = tarfile.FIFOTYPE
                tar_obj.addfile(member)
            archive.seek(0)
            with tarfile.open(fileobj=archive, mode='r:') as tar_obj:
                with self.assertRaises(ValueError):
                    libc_tool.safe_extract_tar(tar_obj, temp_dir)

    def test_download_cache_requires_integrity_metadata(self):
        package_url = 'https://example.test/pool/libc6_1_amd64.deb'
        package_data = b'not-a-real-deb-but-the-extractor-is-stubbed'
        package_sha256 = hashlib.sha256(package_data).hexdigest()
        with tempfile.TemporaryDirectory() as temp_dir:
            old_cache = os.environ.get('LIBC_TOOL_CACHE_DIR')
            old_context_cache = libc_tool.context.cache_dir
            try:
                os.environ['LIBC_TOOL_CACHE_DIR'] = temp_dir
                libc_tool.PACKAGE_METADATA_CACHE.clear()
                libc_tool.remember_package_metadata(
                    package_url,
                    {
                        'package_sha256': package_sha256,
                        'package_size': len(package_data),
                        'package_filename': 'libc6_1_amd64.deb',
                    },
                )
                fake_db = SimpleNamespace(wget=mock.Mock(return_value=package_data))

                def fake_extract(cache_dir, _filename, _data):
                    os.makedirs(os.path.join(cache_dir, 'usr', 'lib'), exist_ok=True)
                    with open(os.path.join(cache_dir, 'usr', 'lib', 'libc.so.6'), 'wb') as file_obj:
                        file_obj.write(b'ELF')

                with mock.patch.object(libc_tool, 'libcdb', fake_db), mock.patch.object(
                    libc_tool, 'extract_all_from_deb', side_effect=fake_extract
                ):
                    first = libc_tool.download_and_extract_deb_package(package_url, 'unit-cache')
                    second = libc_tool.download_and_extract_deb_package(package_url, 'unit-cache')
                self.assertEqual(first, second)
                self.assertEqual(fake_db.wget.call_count, 1)
                with open(os.path.join(first, libc_tool.PACKAGE_CACHE_MARKER), 'r', encoding='utf-8') as file_obj:
                    marker = json.load(file_obj)
                self.assertEqual(marker['package_sha256'], package_sha256)
            finally:
                if old_cache is None:
                    os.environ.pop('LIBC_TOOL_CACHE_DIR', None)
                else:
                    os.environ['LIBC_TOOL_CACHE_DIR'] = old_cache
                libc_tool.context.cache_dir = old_context_cache

    def test_template_profile_changes_launcher(self):
        socat = libc_tool.docker_template_profile('ubuntu+socat')
        xinetd = libc_tool.docker_template_profile('ubuntu+xinetd+chroot')
        self.assertEqual(socat['launcher'], 'socat')
        self.assertEqual(xinetd['launcher'], 'xinetd')
        dockerfile = libc_tool.render_dockerfile(
            'ubuntu:20.04',
            'ubuntu+xinetd+chroot',
            template_profile=xinetd,
        )
        self.assertIn('CMD xinetd -f /etc/ctf.xinetd', dockerfile)
        self.assertNotIn('CMD socat tcp-l:1337', dockerfile)


if __name__ == '__main__':
    unittest.main()
