"""Run the installer in a temporary sandbox with a controlled Python self-test.

No root, packages, containers or live network are used. Production paths are
redirected into the sandbox and the Python executable is a test double.
"""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


INSTALLER = Path(__file__).resolve().parents[1] / 'install-alpine.sh'


@unittest.skipIf(os.name == 'nt' or not shutil.which('sh'), 'POSIX shell required')
class InstallerTests(unittest.TestCase):
    def run_installer(self, unit_exit):
        with tempfile.TemporaryDirectory(prefix='portal-installer-') as directory:
            root = Path(directory)
            source = root / 'source'
            deploy = source / 'deploy'
            deploy.mkdir(parents=True)
            tests = source / 'tests'
            tests.mkdir()
            (tests / 'test_fixture.py').write_text('# synthetic fixture\n')
            for name in ('portal_active_probe.py', 'portal_auto.py',
                         'portal_auto_platform.py', 'portal_capture.py',
                         'portal_egress_witness.py', 'portal_windows.py',
                         'portal_windows_network.py', 'protocol.py',
                         'requirements.txt', 'LICENSE'):
                (source / name).write_text('# installer fixture\n')
            (deploy / 'portal').write_text('#!/bin/sh\nprintf "fixture version\\n"\n')
            (deploy / 'portal-bitrate.initd').write_text('# fixture\n')

            app = root / 'app'
            binary = app / '.venv' / 'bin' / 'python'
            binary.parent.mkdir(parents=True)
            binary.write_text(
                '#!/bin/sh\n'
                'case "$*" in\n'
                '  *"unittest discover"*)\n'
                '    printf "full self-test output\\n"\n'
                '    printf "self-test diagnostic\\n" >&2\n'
                f'    exit {unit_exit} ;;\n'
                '  *) exit 0 ;;\n'
                'esac\n'
            )
            binary.chmod(0o755)
            helper = root / 'bin' / 'portal'
            helper.parent.mkdir()
            shim = root / 'path-bin' / 'portal'
            shim.parent.mkdir()
            script = INSTALLER.read_text()
            for original, destination in (
                ('/opt/portal-bitrate-auto', app),
                ('/var/lib/portal-bitrate-auto', root / 'runtime'),
                ('/etc/portal-bitrate', root / 'config'),
                ('/usr/local/bin/portal', helper),
                ('/usr/bin/portal', shim),
            ):
                script = script.replace(original, str(destination))
            installer = deploy / 'install-alpine.sh'
            installer.write_text(script)
            environment = dict(os.environ, PORTAL_CONTAINER='1', PORTAL_SKIP_APK='1')
            result = subprocess.run(['sh', str(installer)], env=environment,
                                    capture_output=True, text=True, timeout=30)
            return result, helper.exists(), shim.is_symlink()

    def test_failed_self_test_stops_before_helper_install(self):
        result, helper_installed, shim_installed = self.run_installer(7)
        self.assertEqual(result.returncode, 7, result.stdout + result.stderr)
        self.assertIn('self-test diagnostic', result.stderr)
        self.assertFalse(helper_installed)
        self.assertFalse(shim_installed)
        self.assertNotIn('==> Installed:', result.stdout)

    def test_successful_self_test_installs_helper(self):
        result, helper_installed, shim_installed = self.run_installer(0)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('full self-test output', result.stdout)
        self.assertTrue(helper_installed)
        self.assertTrue(shim_installed)
        self.assertIn('==> Installed: fixture version', result.stdout)


if __name__ == '__main__':
    unittest.main(verbosity=2)
