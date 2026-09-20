#!/usr/bin/env python3
"""Keep the CI contract from silently losing coverage or accepting a wrong cache."""
import copy
import json
from pathlib import Path
import tempfile
import tarfile
import unittest
from unittest.mock import patch

import kernel
import matrix


class MatrixTests(unittest.TestCase):
    def test_required_coverage(self):
        pr = matrix.matrix('pr')['include']
        full = matrix.matrix('full')['include']
        self.assertTrue(pr)
        self.assertTrue(all(row in full for row in pr))
        self.assertIn('6.6.142', {row['kernel'] for row in pr})
        self.assertEqual(len(pr), 16)
        self.assertEqual(len(full), 52)
        self.assertEqual({row['kernel'] for row in full}, {k['version'] for k in matrix.kernels()})
        for rows in (pr, full):
            ids = {(r['kernel'], r['arch'], r['pages'], r['usbmon']) for r in rows}
            self.assertEqual(len(ids), len(rows))
            for version in {r['kernel'] for r in rows}:
                entry = next(k for k in matrix.kernels() if k['version'] == version)
                targets = [('x86_64', '4K'), ('aarch64', '4K'), ('aarch64', '64K')]
                if entry['arm64_big_endian']:
                    targets += [('aarch64_be', '4K'), ('aarch64_be', '64K')]
                self.assertEqual({(a, p, m) for v, a, p, m in ids if v == version}, {
                    (a, p, m) for a, p in targets
                    for m in ('n', 'y')})

    def test_reject_bad_manifest(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'kernels.json'
            good = matrix.kernels()[0]
            for bad in [[], [good, good], [dict(good, sha256='unchecked')],
                        [dict(good, version='../../linux')], [dict(good, pr='false')],
                        [dict(good, arm64_big_endian='false')]]:
                with self.subTest(bad=bad), self.assertRaises(ValueError):
                    path.write_text(json.dumps({'kernels': bad}))
                    matrix.kernels(path)


class KernelCacheTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.bundle = Path(self.temp.name)
        self.expected = {'version': '6.6.142', 'source_sha256': matrix.kernels()[0]['sha256'],
                         'arch': 'aarch64', 'pages': '64K', 'usbmon': 'n'}
        (self.bundle / 'kernel').write_bytes(b'kernel image')
        (self.bundle / 'usbscope_iso.ko').write_bytes(b'kernel module')
        (self.bundle / 'config').write_text(
            '# CONFIG_USB_MON is not set\nCONFIG_DEBUG_INFO_BTF=y\nCONFIG_IKCONFIG_PROC=y\n'
            'CONFIG_ARM64=y\nCONFIG_ARM64_64K_PAGES=y\nCONFIG_ARM64_VA_BITS=48\n'
            '# CONFIG_CPU_BIG_ENDIAN is not set\nCONFIG_CPU_LITTLE_ENDIAN=y\n')
        self.metadata = dict(self.expected, kernel_release='6.6.142', files={
            name: kernel.sha256(self.bundle / name) for name in ('kernel', 'config', 'usbscope_iso.ko')})
        self.write_metadata(self.metadata)

    def write_metadata(self, value):
        (self.bundle / 'metadata.json').write_text(json.dumps(value))

    def test_correct_cache(self):
        self.assertEqual(kernel.verify(self.bundle, self.expected), self.metadata)

    def test_little_endian_cache_without_big_endian_option(self):
        # Linux 6.18+ hides CPU_BIG_ENDIAN behind BROKEN, omitting even its "not set" line.
        config = self.bundle / 'config'
        config.write_text(config.read_text().replace('# CONFIG_CPU_BIG_ENDIAN is not set\n', ''))
        metadata = copy.deepcopy(self.metadata)
        metadata['files']['config'] = kernel.sha256(config)
        self.write_metadata(metadata)
        self.assertEqual(kernel.verify(self.bundle, self.expected), metadata)

    def test_little_endian_cache_rejects_big_endian_kernel(self):
        config = self.bundle / 'config'
        config.write_text(config.read_text().replace(
            '# CONFIG_CPU_BIG_ENDIAN is not set\nCONFIG_CPU_LITTLE_ENDIAN=y',
            'CONFIG_CPU_BIG_ENDIAN=y'))
        metadata = copy.deepcopy(self.metadata)
        metadata['files']['config'] = kernel.sha256(config)
        self.write_metadata(metadata)
        with self.assertRaisesRegex(ValueError, 'CPU_LITTLE_ENDIAN'):
            kernel.verify(self.bundle, self.expected)

    def test_wrong_identity(self):
        for key, value in [('arch', 'x86_64'), ('pages', '4K'), ('usbmon', 'y'),
                           ('version', '6.8'), ('source_sha256', '0' * 64), ('kernel_release', '6.8.0')]:
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.write_metadata(dict(self.metadata, **{key: value}))
                kernel.verify(self.bundle, self.expected)

    def test_modified_artifact(self):
        (self.bundle / 'kernel').write_bytes(b'other kernel')
        with self.assertRaisesRegex(ValueError, 'checksum mismatch'):
            kernel.verify(self.bundle, self.expected)

    def test_big_endian_cache_requires_big_endian_kernel(self):
        expected = dict(self.expected, arch='aarch64_be')
        metadata = dict(self.metadata, arch='aarch64_be')
        self.write_metadata(metadata)
        with self.assertRaisesRegex(ValueError, 'CPU_BIG_ENDIAN'):
            kernel.verify(self.bundle, expected)
        config = self.bundle / 'config'
        config.write_text(config.read_text().replace(
            '# CONFIG_CPU_BIG_ENDIAN is not set\nCONFIG_CPU_LITTLE_ENDIAN=y',
            'CONFIG_CPU_BIG_ENDIAN=y'))
        metadata = copy.deepcopy(metadata)
        metadata['files']['config'] = kernel.sha256(config)
        self.write_metadata(metadata)
        self.assertEqual(kernel.verify(self.bundle, expected), metadata)

    def test_config_disagrees_with_metadata(self):
        config = self.bundle / 'config'
        config.write_text(config.read_text().replace('CONFIG_ARM64_64K_PAGES=y', 'CONFIG_ARM64_4K_PAGES=y'))
        metadata = copy.deepcopy(self.metadata)
        metadata['files']['config'] = kernel.sha256(config)
        self.write_metadata(metadata)
        with self.assertRaisesRegex(ValueError, 'ARM64_64K_PAGES'):
            kernel.verify(self.bundle, self.expected)

    def test_unverified_source_is_never_extracted(self):
        archive = self.bundle / 'linux-6.6.142.tar.xz'
        archive.write_bytes(b'truncated or modified download')
        with self.assertRaisesRegex(ValueError, 'SHA-256 mismatch'):
            kernel.source_tree(matrix.kernels()[0], self.bundle)
        self.assertFalse((self.bundle / 'linux-6.6.142').exists())

    def test_download_failure_uses_verified_fallback(self):
        fixture = self.bundle / 'fixture'
        fixture.write_bytes(b'kernel fixture')
        archive = self.bundle / 'fixture.tar.xz'
        with tarfile.open(archive, 'w:xz') as tar:
            tar.add(fixture, arcname='linux-6.6.142/Makefile')
        entry = dict(matrix.kernels()[0], sha256=kernel.sha256(archive))
        urls = []
        real_run = kernel.subprocess.run

        def transfer(command, **kwargs):
            if command[0] != 'curl':
                return real_run(command, **kwargs)
            urls.append(command[-1])
            destination = Path(command[command.index('--output') + 1])
            destination.write_bytes(b'partial' if len(urls) == 1 else archive.read_bytes())
            return kernel.subprocess.CompletedProcess(command, 28 if len(urls) == 1 else 0)

        with patch('kernel.subprocess.run', side_effect=transfer):
            source = kernel.source_tree(entry, self.bundle)
        self.assertEqual(len(urls), 2)
        self.assertEqual((source / 'Makefile').read_bytes(), fixture.read_bytes())
        self.assertEqual((source / '.usbscope-source-sha256').read_text().strip(), entry['sha256'])


if __name__ == '__main__':
    unittest.main()
