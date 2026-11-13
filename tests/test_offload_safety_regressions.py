import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import space_guard_agent as guard


class DataSafetyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.state = self.root / 'state'
        self.state.mkdir()
        for name, value in [('STATE_DIR', self.state), ('CONFIG_FILE', self.state / 'config.json'), ('LEDGER_FILE', self.state / 'ledger.json')]:
            patcher = patch.object(guard, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def test_real_offload_fails_closed_for_file_and_directory(self):
        src = self.root / 'project'
        (src / 'node_modules').mkdir(parents=True)
        original = src / 'node_modules' / 'unique'
        original.write_text('valuable content')
        for item in (src, original):
            result = guard.verify_and_offload_file(str(item))
            self.assertFalse(result['ok'])
            self.assertEqual(original.read_text(), 'valuable content')
            self.assertFalse(Path(str(item) + '.cloudstub').exists())

    def make_stub(self, target, is_dir=False):
        vault = self.root / 'vault'
        vault.write_bytes(b'previous content')
        stub = self.root / 'receipt.cloudstub'
        stub.write_text(json.dumps({'original_path': str(target), 'cloud_vault_path': str(vault), 'sha256': hashlib.sha256(vault.read_bytes()).hexdigest(), 'is_directory_archive': is_dir}))
        return stub

    def test_restore_rejects_existing_file_and_keeps_stub(self):
        target = self.root / 'target'
        target.write_text('new work')
        stub = self.make_stub(target)
        self.assertFalse(guard.restore_from_stub(str(stub))['ok'])
        self.assertEqual(target.read_text(), 'new work')
        self.assertTrue(stub.exists())

    def test_restore_rejects_dangling_symlink(self):
        target = self.root / 'target'
        target.symlink_to(self.root / 'missing')
        stub = self.make_stub(target)
        self.assertFalse(guard.restore_from_stub(str(stub))['ok'])
        self.assertTrue(target.is_symlink())
        self.assertTrue(stub.exists())

    def test_file_restore_succeeds_when_absent(self):
        target = self.root / 'target'
        stub = self.make_stub(target)
        self.assertTrue(guard.restore_from_stub(str(stub))['ok'])
        self.assertEqual(target.read_bytes(), b'previous content')
        self.assertFalse(stub.exists())

    def test_legacy_directory_restore_is_blocked(self):
        target = self.root / 'project'
        stub = self.make_stub(target, is_dir=True)
        self.assertFalse(guard.restore_from_stub(str(stub))['ok'])
        self.assertFalse(target.exists())
        self.assertTrue(stub.exists())


if __name__ == '__main__':
    unittest.main()
