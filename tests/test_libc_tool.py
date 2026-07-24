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

    def test_docker_debug_runtime_is_scoped_and_gdb_is_retryable(self):
        run_script = libc_tool.render_docker_run_script()
        challenge_script = libc_tool.render_docker_challenge_script(
            '/challenge',
            'exec /tmp/libc_tool_exec_pwn',
        )
        gdb_script = libc_tool.render_docker_gdb_script(
            'bundle/challenge/pwn',
            'bundle/runtime',
            'bundle/challenge',
            enable_gdbserver=True,
            gdb_port=1234,
            host_port=10001,
        )

        self.assertIn('LIBC_TOOL_LIBRARY_PATH', run_script)
        self.assertIn('gdbserver "${gdbserver_options[@]}" --wrapper env', run_script)
        self.assertIn('gdbserver_options=(--once --no-disable-randomization)', run_script)
        self.assertIn('export LD_LIBRARY_PATH="$runtime_library_path"', challenge_script)
        self.assertNotIn('LD_LIBRARY_PATH:', run_script)
        self.assertIn('bundle_dir = os.path.commonpath([challenge_dir, runtime_dir])', gdb_script)
        self.assertIn("_libc_tool_run(f'set sysroot {bundle_dir}')", gdb_script)
        self.assertNotIn("_libc_tool_gdb_quote(bundle_dir)", gdb_script)
        self.assertNotIn('.gdb_sysroot', gdb_script)
        self.assertIn('LIBC_TOOL_GDB_WAIT', gdb_script)
        self.assertIn('set disable-randomization off', gdb_script)
        self.assertIn('set follow-fork-mode parent', gdb_script)
        self.assertIn('set detach-on-fork on', gdb_script)
        self.assertNotIn('set detach-on-fork off', gdb_script)
        self.assertIn("gdb.execute('disconnect', to_string=True)", gdb_script)
        self.assertIn("gdb.execute('sharedlibrary', to_string=True)", gdb_script)
        self.assertIn('target remote 127.0.0.1:1234', gdb_script)

    def test_docker_destroy_selection_supports_lists_ranges_and_all(self):
        self.assertEqual(
            libc_tool.parse_docker_target_selection('0, 2, 4', 5),
            [0, 2, 4],
        )
        self.assertEqual(
            libc_tool.parse_docker_target_selection('3-1', 5),
            [1, 2, 3],
        )
        self.assertEqual(
            libc_tool.parse_docker_target_selection('all', 3),
            [0, 1, 2],
        )
        with self.assertRaises(ValueError):
            libc_tool.parse_docker_target_selection('0,9', 3)

    def test_docker_prepare_script_supports_relative_elf_interpreter(self):
        prepare_script = libc_tool.render_docker_gdb_prepare_script(
            '/runtime',
            '/challenge/heap',
            '/tmp/libc_tool_exec_heap',
            interpreter_path='libc_dir/ld-linux-x86-64.so.2',
            runtime_loader_path='/runtime/ld-linux-x86-64.so.2',
        )
        self.assertIn('interpreter_path=libc_dir/ld-linux-x86-64.so.2', prepare_script)
        self.assertIn('runtime_loader_path=/runtime/ld-linux-x86-64.so.2', prepare_script)
        self.assertIn('interpreter_link="$base_dir/$interpreter_path"', prepare_script)
        self.assertIn('ln -s "$runtime_loader_path" "$interpreter_link"', prepare_script)

    def test_docker_prefer_local_parser_and_runtime_probe(self):
        parser = libc_tool.build_cli_parser()
        args = parser.parse_args(['docker', '--prefer-local', 'shop'])
        self.assertTrue(args.prefer_local)

        with tempfile.TemporaryDirectory() as temp_dir:
            elf_path = os.path.join(temp_dir, 'shop')
            libc_path = os.path.join(temp_dir, 'libc.so.6')
            with open(elf_path, 'wb') as file_obj:
                file_obj.write(b'ELF')
            with open(libc_path, 'wb') as file_obj:
                file_obj.write(b'ELF')
            probe = {
                'ok': True,
                'target_dir': temp_dir,
                'loader_path': os.path.join(temp_dir, 'ld-linux-x86-64.so.2'),
            }
            with mock.patch.object(libc_tool, 'list_default_libc_candidates', return_value=[libc_path]), \
                    mock.patch.object(libc_tool, 'inspect_local_runtime_dir_for_libc', return_value=probe), \
                    mock.patch.object(libc_tool, 'describe_local_libc', return_value='Ubuntu GLIBC 2.43'):
                local_runtime = libc_tool.find_local_runtime_for_docker(elf_path)

            self.assertEqual(local_runtime['libc_path'], libc_path)
            self.assertEqual(local_runtime['runtime_dir'], temp_dir)
            self.assertEqual(local_runtime['version'], 'Ubuntu GLIBC 2.43')

    def test_docker_deploy_dir_cleanup_is_guarded(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            generated_dir = os.path.join(temp_dir, '.libc_tool_docker_pwn')
            os.makedirs(generated_dir)
            self.assertTrue(libc_tool.remove_docker_deploy_dir(generated_dir))
            self.assertFalse(os.path.exists(generated_dir))

            custom_dir = os.path.join(temp_dir, 'custom-deploy')
            os.makedirs(custom_dir)
            with self.assertRaises(RuntimeError):
                libc_tool.remove_docker_deploy_dir(custom_dir)
            self.assertTrue(libc_tool.remove_docker_deploy_dir(custom_dir, allow_custom=True))

    def test_docker_down_removes_default_deploy_dir(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            elf_path = os.path.join(temp_dir, 'ez_shellcode')
            with open(elf_path, 'wb') as file_obj:
                file_obj.write(b'\x7fELF')
            deploy_dir = libc_tool.default_docker_deploy_dir(elf_path)
            os.makedirs(deploy_dir)

            parser = libc_tool.build_cli_parser()
            args = parser.parse_args(['docker', '--down', elf_path])
            with mock.patch.object(libc_tool, 'run_docker_compose_action') as compose_action:
                libc_tool.run_docker_command(args, parser)

            compose_action.assert_called_once_with(deploy_dir, ['down'])
            self.assertFalse(os.path.exists(deploy_dir))

    def test_docker_destroy_yes_processes_all_targets_after_failure(self):
        targets = [
            {'kind': 'deployment', 'display_name': 'first'},
            {'kind': 'image', 'display_name': 'second', 'image_name': 'libc_tool_docker_second'},
        ]

        def destroy_target(target):
            if target is targets[0]:
                raise RuntimeError('test failure')
            return {
                'mode': 'direct',
                'deploy_dir': '',
                'image_error': '',
                'deploy_dir_error': '',
                'deploy_dir_removed': False,
            }

        parser = libc_tool.build_cli_parser()
        args = parser.parse_args(['docker', '--destroy', '-y'])
        with mock.patch.object(libc_tool, 'collect_libc_tool_docker_targets', return_value=targets), \
                mock.patch.object(libc_tool, 'destroy_libc_tool_docker_target', side_effect=destroy_target) as destroy:
            with self.assertRaises(SystemExit) as exit_info:
                libc_tool.run_docker_command(args, parser)

        self.assertEqual(exit_info.exception.code, 1)
        self.assertEqual(destroy.call_count, len(targets))

    def test_docker_bundle_excludes_nested_runtime_and_old_deployments(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            challenge_dir = os.path.join(temp_dir, 'challenge')
            runtime_dir = os.path.join(challenge_dir, 'libc_dir')
            deploy_dir = os.path.join(challenge_dir, '.libc_tool_docker_current')
            old_deploy_dir = os.path.join(challenge_dir, '.libc_tool_docker_old')
            os.makedirs(runtime_dir)
            os.makedirs(deploy_dir)
            os.makedirs(old_deploy_dir)

            excluded = set(libc_tool.docker_challenge_exclude_paths(
                challenge_dir,
                runtime_dir,
                deploy_dir,
            ))

            self.assertIn(os.path.abspath(runtime_dir), excluded)
            self.assertIn(os.path.abspath(deploy_dir), excluded)
            self.assertIn(os.path.abspath(old_deploy_dir), excluded)

            runtime_excluded = set(libc_tool.docker_runtime_exclude_paths(
                challenge_dir,
                deploy_dir,
            ))
            self.assertIn(os.path.abspath(deploy_dir), runtime_excluded)
            self.assertIn(os.path.abspath(old_deploy_dir), runtime_excluded)

            marker_path = os.path.join(challenge_dir, 'libc.so.6')
            with open(marker_path, 'wb') as file_obj:
                file_obj.write(b'local libc')
            runtime_bundle = os.path.join(deploy_dir, 'bundle', 'runtime')
            libc_tool.copy_portable_tree(
                challenge_dir,
                runtime_bundle,
                exclude_paths=runtime_excluded,
            )
            self.assertTrue(os.path.exists(os.path.join(runtime_bundle, 'libc.so.6')))
            self.assertFalse(os.path.exists(os.path.join(
                runtime_bundle,
                os.path.basename(deploy_dir),
            )))

    def test_library_scan_ignores_generated_docker_directories(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            direct_libc = os.path.join(temp_dir, 'libc.so.6')
            generated_dir = os.path.join(temp_dir, '.libc_tool_docker_old', 'bundle', 'challenge')
            nested_libc = os.path.join(generated_dir, 'libc.so.6')
            os.makedirs(generated_dir)
            with open(direct_libc, 'wb') as file_obj:
                file_obj.write(b'direct')
            with open(nested_libc, 'wb') as file_obj:
                file_obj.write(b'nested')

            self.assertEqual(
                libc_tool.find_library_artifact(temp_dir, 'libc.so.6'),
                direct_libc,
            )


if __name__ == '__main__':
    unittest.main()
