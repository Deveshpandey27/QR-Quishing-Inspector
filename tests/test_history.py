import unittest
from fastapi.testclient import TestClient
from app.main import app
from app.services.history_service import (
    get_history,
    record_scan,
    get_scan_by_id,
    clear_history,
    reset_seed_history,
    _format_relative_date,
)


class TestScanHistory(unittest.TestCase):

    def setUp(self):
        self.client = TestClient(app)
        reset_seed_history()

    def tearDown(self):
        reset_seed_history()

    def test_seed_items_exact_match(self):
        """Verify the 4 exact required seed items from the prompt exist with correct Risk and Date."""
        items = get_history()
        self.assertGreaterEqual(len(items), 4)

        lookup = {item['url']: item for item in items}

        # 1. google.com -> LOW, Today
        self.assertIn('google.com', lookup)
        self.assertEqual(lookup['google.com']['risk_level'], 'LOW')
        self.assertEqual(lookup['google.com']['relative_date'], 'Today')

        # 2. example.xyz -> HIGH, Today
        self.assertIn('example.xyz', lookup)
        self.assertEqual(lookup['example.xyz']['risk_level'], 'HIGH')
        self.assertEqual(lookup['example.xyz']['relative_date'], 'Today')

        # 3. bit.ly/abc123 -> MEDIUM, Yesterday
        self.assertIn('bit.ly/abc123', lookup)
        self.assertEqual(lookup['bit.ly/abc123']['risk_level'], 'MEDIUM')
        self.assertEqual(lookup['bit.ly/abc123']['relative_date'], 'Yesterday')

        # 4. bank-login.xyz -> HIGH, Yesterday
        self.assertIn('bank-login.xyz', lookup)
        self.assertEqual(lookup['bank-login.xyz']['risk_level'], 'HIGH')
        self.assertEqual(lookup['bank-login.xyz']['relative_date'], 'Yesterday')

    def test_filter_by_risk(self):
        """Verify filtering by risk level returns only matching items."""
        high_items = get_history(risk_filter='HIGH')
        self.assertTrue(all(item['risk_level'] == 'HIGH' for item in high_items))
        self.assertGreaterEqual(len(high_items), 2)

        low_items = get_history(risk_filter='LOW')
        self.assertTrue(all(item['risk_level'] == 'LOW' for item in low_items))

        med_items = get_history(risk_filter='MEDIUM')
        self.assertTrue(all(item['risk_level'] == 'MEDIUM' for item in med_items))

    def test_filter_by_search_query(self):
        """Verify searching by URL keyword filters results appropriately."""
        results = get_history(query='google')
        self.assertTrue(any(item['url'] == 'google.com' for item in results))
        self.assertFalse(any('bank-login' in item['url'] for item in results))

    def test_record_scan_and_get_by_id(self):
        """Verify recording a new scan persists it and assigns an ID and Today label."""
        new_scan = {
            'url': 'https://malicious-portal-update.com/login',
            'risk_level': 'HIGH',
            'final_score': 89,
            'reasons': ['Suspicious keyword login', 'High ML score'],
            'analysis_snapshot': {
                'url': 'https://malicious-portal-update.com/login',
                'score': 89,
                'status': 'dangerous'
            }
        }
        saved = record_scan(new_scan)
        self.assertIsNotNone(saved.get('id'))
        self.assertEqual(saved['url'], new_scan['url'])
        self.assertEqual(saved['risk_level'], 'HIGH')
        self.assertEqual(saved['relative_date'], 'Today')

        fetched = get_scan_by_id(saved['id'])
        self.assertIsNotNone(fetched)
        self.assertEqual(fetched['id'], saved['id'])
        self.assertEqual(fetched['final_score'], 89)
        self.assertEqual(fetched['analysis_snapshot']['score'], 89)

    def test_api_get_history(self):
        """Verify GET /api/v1/history returns 200 with items list and total count."""
        res = self.client.get('/api/v1/history')
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertIn('items', data)
        self.assertIn('total', data)
        self.assertGreaterEqual(data['total'], 4)

    def test_api_get_history_with_filters(self):
        """Verify GET /api/v1/history query params filter risk and search."""
        res = self.client.get('/api/v1/history?risk=HIGH')
        self.assertEqual(res.status_code, 200)
        items = res.json()['items']
        for it in items:
            self.assertEqual(it['risk_level'], 'HIGH')

        res_q = self.client.get('/api/v1/history?q=bit.ly')
        self.assertEqual(res_q.status_code, 200)
        q_items = res_q.json()['items']
        self.assertTrue(any('bit.ly' in it['url'] for it in q_items))

    def test_api_post_history(self):
        """Verify POST /api/v1/history adds a scan record."""
        payload = {
            'url': 'https://test-api-history-item.com',
            'risk_level': 'LOW',
            'final_score': 10,
            'reasons': ['Authentic domain'],
            'analysis_snapshot': {'url': 'https://test-api-history-item.com', 'score': 10}
        }
        res = self.client.post('/api/v1/history', json=payload)
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertTrue(data['success'])
        self.assertEqual(data['item']['url'], payload['url'])

    def test_api_get_by_id_and_not_found(self):
        """Verify GET /api/v1/history/{id} and 404 behavior."""
        items = get_history()
        scan_id = items[0]['id']
        res = self.client.get(f'/api/v1/history/{scan_id}')
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()['id'], scan_id)

        res_404 = self.client.get('/api/v1/history/non-existent-scan-id')
        self.assertEqual(res_404.status_code, 404)

    def test_api_clear_and_reset(self):
        """Verify DELETE /api/v1/history clears data and POST /reset restores seeds."""
        res_del = self.client.delete('/api/v1/history')
        self.assertEqual(res_del.status_code, 200)

        res_empty = self.client.get('/api/v1/history')
        self.assertEqual(res_empty.json()['total'], 0)

        res_reset = self.client.post('/api/v1/history/reset')
        self.assertEqual(res_reset.status_code, 200)

        res_restored = self.client.get('/api/v1/history')
        self.assertEqual(res_restored.json()['total'], 4)


if __name__ == '__main__':
    unittest.main()
