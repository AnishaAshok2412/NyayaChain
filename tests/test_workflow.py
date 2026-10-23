import unittest
import nyayachain_dissertation as n
from demo import run_demo


class WorkflowTests(unittest.TestCase):
    def test_workflow_encryption_and_report(self):
        self.assertTrue(n._AES_AVAILABLE, 'Install requirements before testing')
        bc, eid, reports = run_demo()
        encrypted = bc.chain[-1]['records'][-1]['encrypted']
        self.assertNotIn('plain', encrypted)
        self.assertEqual(n.aes_decrypt_json(encrypted)['evidence_id'], eid)
        self.assertIn('SI Alice Carter', reports['evidence_report.txt'])
        with self.assertRaises(PermissionError):
            bc.mine_block(n.SEED_USERS['C001'])
        with self.assertRaises(ValueError):
            bc.add_evidence_record(n.SEED_USERS['P001'], 'Demo', 'P001', 'DEMO',
                'Demo', 'Demo', 'text', 'Robbery (Sec. 309)', {})
        bc.world_state[eid].history[0].payload['case_id'] = 'TAMPERED'
        self.assertFalse(n.ReportGenerator(bc)._verify_history_chain(bc.world_state[eid]))
        proof = bc.chain[-1]['proof'] + 1
        while bc._valid_proof(bc.chain[0]['proof'], proof, bc.hash(bc.chain[0])):
            proof += 1
        bc.chain[-1]['proof'] = proof
        self.assertFalse(bc.verify_chain())


if __name__ == '__main__':
    unittest.main()
