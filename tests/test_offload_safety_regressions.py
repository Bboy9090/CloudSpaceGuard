import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
import space_guard_agent as guard

class DataSafetyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name); self.state = self.root / 'state'; self.state.mkdir()
        self.vault = self.root / 'vault'; self.vault.mkdir()
        for name, value in [('STATE_DIR', self.state), ('CONFIG_FILE', self.state/'config.json'), ('LEDGER_FILE', self.state/'ledger.json')]:
            p = patch.object(guard, name, value); p.start(); self.addCleanup(p.stop)
        p = patch.object(guard, 'discover_cloud_providers', return_value=[{'id':'test', 'name':'Test', 'vault_path':str(self.vault)}]); p.start(); self.addCleanup(p.stop)
    def make_stub(self, target, is_dir=False):
        vault=self.root/'saved'; vault.write_bytes(b'previous content'); stub=self.root/'receipt.cloudstub'
        stub.write_text(json.dumps({'original_path':str(target),'cloud_vault_path':str(vault),'sha256':hashlib.sha256(vault.read_bytes()).hexdigest(),'is_directory_archive':is_dir})); return stub
    def test_colliding_names_keep_distinct_copies_and_sources(self):
        paths=[self.root/'a'/'same'/'note', self.root/'b'/'same'/'note']
        results=[]
        for i,p in enumerate(paths):
            p.parent.mkdir(parents=True); p.write_text(str(i)); results.append(guard.verify_and_offload_file(str(p), 'test'))
        self.assertTrue(all(r['ok'] for r in results)); self.assertNotEqual(results[0]['entry']['cloud_destination'], results[1]['entry']['cloud_destination'])
        for i,p in enumerate(paths):
            self.assertEqual(p.read_text(),str(i)); self.assertEqual(Path(results[i]['entry']['cloud_destination']).read_text(),str(i)); self.assertFalse(results[i]['remote_durability_verified'])
    def test_archive_preserves_previously_excluded_data_and_source(self):
        import tarfile
        src=self.root/'project'; (src/'node_modules').mkdir(parents=True); (src/'node_modules'/'unique').write_text('important')
        r=guard.verify_and_offload_file(str(src),'test'); self.assertTrue(r['ok']); self.assertEqual((src/'node_modules'/'unique').read_text(),'important')
        with tarfile.open(r['entry']['cloud_destination'],'r:gz') as tar: self.assertEqual(tar.extractfile('project/node_modules/unique').read(),b'important')
    def test_existing_receipt_is_not_overwritten(self):
        src=self.root/'item'; src.write_text('source'); receipt=Path(str(src)+'.cloudstub'); receipt.write_text('old receipt')
        self.assertFalse(guard.verify_and_offload_file(str(src),'test')['ok']); self.assertEqual(receipt.read_text(),'old receipt'); self.assertTrue(src.exists())
    def test_restore_rejects_existing_file_and_symlink(self):
        target=self.root/'target'; target.write_text('new work'); stub=self.make_stub(target)
        self.assertFalse(guard.restore_from_stub(str(stub))['ok']); self.assertEqual(target.read_text(),'new work'); target.unlink(); target.symlink_to(self.root/'missing')
        self.assertFalse(guard.restore_from_stub(str(stub))['ok']); self.assertTrue(target.is_symlink()); self.assertTrue(stub.exists())
    def test_file_restore_succeeds_when_absent(self):
        target=self.root/'target'; stub=self.make_stub(target); self.assertTrue(guard.restore_from_stub(str(stub))['ok']); self.assertEqual(target.read_bytes(),b'previous content'); self.assertFalse(stub.exists())
    def test_legacy_directory_restore_is_blocked(self):
        target=self.root/'project'; stub=self.make_stub(target,True); self.assertFalse(guard.restore_from_stub(str(stub))['ok']); self.assertFalse(target.exists()); self.assertTrue(stub.exists())
    def test_unknown_provider_never_falls_back(self):
        src=self.root/'source'; src.write_text('data'); self.assertFalse(guard.verify_and_offload_file(str(src),'missing')['ok']); self.assertTrue(src.exists())
    def test_symlink_in_directory_blocks_copy_without_source_loss(self):
        src=self.root/'project'; src.mkdir(); (src/'link').symlink_to(self.root/'elsewhere'); self.assertFalse(guard.verify_and_offload_file(str(src),'test')['ok']); self.assertTrue((src/'link').is_symlink())
if __name__=='__main__': unittest.main()
