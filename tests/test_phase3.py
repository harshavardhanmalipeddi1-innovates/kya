import hashlib, hmac, json, os, sys, unittest
BACKEND_DIR = os.path.join(os.path.dirname(__file__), '..', 'backend')
sys.path.insert(0, BACKEND_DIR)
os.environ.setdefault('KYA_SIGNING_SECRET', 'test-signing')
os.environ.setdefault('KYA_DEMO_ISSUER_KEY', 'test-key')

class TestWebhookSignature(unittest.TestCase):
    def test_valid_sig(self):
        os.environ['RAZORPAY_WEBHOOK_SECRET'] = 'whsec_test'
        # Force re-read of the module-level variable
        import webhook
        webhook.RAZORPAY_WEBHOOK_SECRET = 'whsec_test'
        body = b'{"event":"payment.captured"}'
        sig = hmac.new(b'whsec_test', body, hashlib.sha256).hexdigest()
        self.assertTrue(webhook.verify_signature(body, sig))
        del os.environ['RAZORPAY_WEBHOOK_SECRET']
    def test_invalid_sig(self):
        from webhook import verify_signature
        os.environ['RAZORPAY_WEBHOOK_SECRET'] = 'whsec_test'
        self.assertFalse(verify_signature(b'body', 'bad'))
        del os.environ['RAZORPAY_WEBHOOK_SECRET']
    def test_no_secret_rejects(self):
        from webhook import verify_signature
        os.environ['RAZORPAY_WEBHOOK_SECRET'] = ''
        self.assertFalse(verify_signature(b'body', 'any'))
        del os.environ['RAZORPAY_WEBHOOK_SECRET']

class TestWebhookDedup(unittest.TestCase):
    def setUp(self):
        from webhook import clear_dedup_store
        clear_dedup_store()
    def test_first_not_dup(self):
        from webhook import is_duplicate_event
        self.assertFalse(is_duplicate_event('evt_1'))
    def test_second_is_dup(self):
        from webhook import is_duplicate_event
        self.assertFalse(is_duplicate_event('evt_2'))
        self.assertTrue(is_duplicate_event('evt_2'))
    def test_different_independent(self):
        from webhook import is_duplicate_event
        self.assertFalse(is_duplicate_event('evt_a'))
        self.assertFalse(is_duplicate_event('evt_b'))

class TestWebhookMapping(unittest.TestCase):
    def test_captured_to_executed(self):
        from webhook import map_event_to_state
        self.assertEqual(map_event_to_state('payment.captured'), 'EXECUTED')
    def test_failed_to_payment_failed(self):
        from webhook import map_event_to_state
        self.assertEqual(map_event_to_state('payment.failed'), 'PAYMENT_FAILED')
    def test_order_created(self):
        from webhook import map_event_to_state
        self.assertEqual(map_event_to_state('order.created'), 'PAYMENT_CREATED')
    def test_unknown_returns_none(self):
        from webhook import map_event_to_state
        self.assertIsNone(map_event_to_state('random.event'))
    def test_parse_event(self):
        from webhook import parse_event
        p = {'event':'payment.captured','id':'evt_1','payload':{'payment':{'entity':{'id':'p1'}},'order':{'entity':{'id':'o1'}}}}
        e = parse_event(p)
        self.assertEqual(e['event_type'], 'payment.captured')
    def test_parse_missing_event(self):
        from webhook import parse_event
        self.assertIsNone(parse_event({'payload':{}}))

class TestReconciliation(unittest.TestCase):
    def test_exact_match_captured(self):
        from reconciliation import reconcile
        from razorpay_mock import MockPaymentProvider, seed_order, seed_payment
        import razorpay_mock
        razorpay_mock.reset_mock()
        p = MockPaymentProvider()
        seed_order('ord_1', 500.0, 'exec_abc', status='paid', agent_id='agent_procure_bot_042')
        seed_payment('ord_1', 'pay_1', status='captured')
        r = reconcile(p, 'exec_abc', agent_id='agent_procure_bot_042', amount=500.0)
        self.assertEqual(r.action, 'finalized')
        self.assertEqual(r.execution_state, 'EXECUTED')
    def test_exact_match_no_payments(self):
        from reconciliation import reconcile
        from razorpay_mock import MockPaymentProvider, seed_order
        import razorpay_mock
        razorpay_mock.reset_mock()
        p = MockPaymentProvider()
        seed_order('ord_2', 500.0, 'exec_def', status='created', agent_id='test')
        r = reconcile(p, 'exec_def', agent_id='test', amount=500.0)
        self.assertEqual(r.action, 'retry')
    def test_no_match_retries(self):
        from reconciliation import reconcile
        from razorpay_mock import MockPaymentProvider
        import razorpay_mock
        razorpay_mock.reset_mock()
        r = reconcile(MockPaymentProvider(), 'exec_xyz', amount=500.0)
        self.assertEqual(r.action, 'retry')
    def test_no_match_eventually_manual(self):
        from reconciliation import reconcile, MAX_AUTO_RECONCILIATION_ATTEMPTS
        from razorpay_mock import MockPaymentProvider
        import razorpay_mock
        razorpay_mock.reset_mock()
        r = reconcile(MockPaymentProvider(), 'exec_xyz', amount=500.0, attempt_number=MAX_AUTO_RECONCILIATION_ATTEMPTS+1)
        self.assertEqual(r.action, 'manual_required')
    def test_retry_delays(self):
        from reconciliation import get_retry_delay
        self.assertEqual(get_retry_delay(1), 0)
        self.assertEqual(get_retry_delay(2), 30)
        self.assertEqual(get_retry_delay(3), 300)

class TestProviderHardening(unittest.TestCase):
    def test_validate_nan(self):
        from razorpay_provider import RazorpayProvider
        with self.assertRaises(ValueError):
            RazorpayProvider._validate_amount(float('nan'))
    def test_validate_negative(self):
        from razorpay_provider import RazorpayProvider
        with self.assertRaises(ValueError):
            RazorpayProvider._validate_amount(-100)
    def test_validate_zero(self):
        from razorpay_provider import RazorpayProvider
        with self.assertRaises(ValueError):
            RazorpayProvider._validate_amount(0)
    def test_validate_paise(self):
        from razorpay_provider import RazorpayProvider
        self.assertEqual(RazorpayProvider._validate_amount(500.0), 50000)
    def test_classify_timeout(self):
        from razorpay_provider import RazorpayProvider, ProviderErrorType
        self.assertEqual(RazorpayProvider._classify_error(Exception('timeout')), ProviderErrorType.TIMEOUT)
    def test_classify_connection(self):
        from razorpay_provider import RazorpayProvider, ProviderErrorType
        self.assertEqual(RazorpayProvider._classify_error(Exception('connection refused')), ProviderErrorType.CONNECTION_ERROR)
    def test_classify_auth(self):
        from razorpay_provider import RazorpayProvider, ProviderErrorType
        self.assertEqual(RazorpayProvider._classify_error(Exception('invalid key auth')), ProviderErrorType.EXPLICIT_REJECTION)

if __name__ == '__main__':
    unittest.main(verbosity=2)
