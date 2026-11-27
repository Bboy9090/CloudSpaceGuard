import hashlib
import json
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
import space_guard_agent as guard

class DirectoryRestoreRaceTests(unittest.TestCase):
    def test_created_destination_is_not_replaced_and_receipt_survives(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = root / 'project'
            source = root / 'source'; source.mkdir(); (source / 'file').write_text('archived')
            archive = root / 'archive.tar.gz'
            with tarfile.open(archive, 'w:gz') as tar: tar.add(source, arcname='project')
            receipt = root / 'receipt.cloudstub'
            receipt.write_text(json.dumps({'original_path': str(original), 'cloud_vault_path': str(archive), 'sha256': hashlib.sha256(archive.read_bytes()).hexdigest(), 'is_directory_archive': True}))
            rename = guard._rename_directory_no_replace
            def race(staged, target):
                Path(target).mkdir()
                return rename(staged, target)
            with patch.object(guard, '_rename_directory_no_replace', side_effect=race), patch.object(guard, 'append_ledger'):
                result = guard.restore_from_stub(str(receipt))
            self.assertFalse(result['ok'])
            self.assertEqual(list(original.iterdir()), [])
            self.assertTrue(receipt.exists())
            original.rmdir()
            with patch.object(guard, 'append_ledger'):
                result = guard.restore_from_stub(str(receipt))
            self.assertTrue(result['ok'], result)
            self.assertEqual((original/'file').read_text(), 'archived')

if __name__ == '__main__': unittest.main()
