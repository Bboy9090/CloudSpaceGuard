import hashlib,json,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
import space_guard_agent as g

class FileRestoreRaceTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup); self.root=Path(self.temp.name)
        self.dest=self.root/'target'; self.vault=self.root/'vault'; self.vault.write_text('archived')
        self.stub=self.root/'receipt'; self.stub.write_text(json.dumps({'original_path':str(self.dest),'cloud_vault_path':str(self.vault),'sha256':hashlib.sha256(self.vault.read_bytes()).hexdigest(),'is_directory_archive':False}))
    def test_concurrent_file_survives_publication(self):
        link=g.os.link
        def race(src,dest):
            Path(dest).write_text('new independent work')
            return link(src,dest)
        with patch.object(g.os,'link',side_effect=race), patch.object(g,'append_ledger'):
            out=g.restore_from_stub(str(self.stub))
        self.assertFalse(out['ok']); self.assertEqual(self.dest.read_text(),'new independent work'); self.assertTrue(self.stub.exists())
    def test_absent_file_restores(self):
        with patch.object(g,'append_ledger'): out=g.restore_from_stub(str(self.stub))
        self.assertTrue(out['ok'],out); self.assertEqual(self.dest.read_text(),'archived'); self.assertFalse(self.stub.exists())
    def test_no_hardlink_support_fails_closed(self):
        with patch.object(g.os,'link',side_effect=OSError('unsupported')), patch.object(g,'append_ledger'):
            out=g.restore_from_stub(str(self.stub))
        self.assertFalse(out['ok']); self.assertFalse(self.dest.exists()); self.assertTrue(self.stub.exists())
if __name__=='__main__': unittest.main()
