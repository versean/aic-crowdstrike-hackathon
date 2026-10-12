"""Navigation, chat context and local-model failure regression checks."""
import sys
import unittest
from pathlib import Path
from unittest.mock import patch, Mock
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from streamlit.testing.v1 import AppTest
from backend_client import load_results, workspace_context, backend_status
from blueteam import llm


class WorkspaceTests(unittest.TestCase):
    def sign_in(self, app, username='admin', password='alertlens'):
        app.text_input(key='login_username').set_value(username)
        app.text_input(key='login_password').set_value(password)
        app.button(key='login_submit').click().run()

    def test_login_gate_and_logout(self):
        app = AppTest.from_file(str(Path(__file__).resolve().parents[1] / 'app.py'), default_timeout=30).run()
        self.assertTrue(any(item.label == 'Username' for item in app.text_input))
        self.assertFalse(any(item.label == 'Workspace' for item in app.radio))
        self.sign_in(app, 'wrong', 'credentials')
        self.assertTrue(any('incorrect' in item.value for item in app.error))
        self.assertFalse(app.session_state.get('authenticated', False))
        self.sign_in(app)
        self.assertTrue(app.session_state['authenticated'])
        self.assertTrue(any(item.label == 'Workspace' for item in app.radio))
        app.button(key='logout_button').click().run()
        self.assertFalse(app.session_state.get('authenticated', False))
        self.assertTrue(any(item.label == 'Username' for item in app.text_input))

    def test_every_page_and_chat_panel(self):
        app = AppTest.from_file(str(Path(__file__).resolve().parents[1] / 'app.py'), default_timeout=30).run()
        self.sign_in(app)
        for page in ('Overview', 'Pipeline & data', 'Incident investigations', 'Alert triage', 'Model quality', 'Ground truth'):
            app.radio[0].set_value(page).run()
            self.assertEqual(list(app.exception), [], page)
            self.assertTrue(any(t.label == 'Open security chat' for t in app.toggle))
        self.assertFalse(any('Brand direction' in s.label for s in app.selectbox))
        app.toggle(key='assistant_open').set_value(True).run()
        self.assertEqual(list(app.exception), [])
        self.assertTrue(any(t.label == 'Ask about security' for t in app.text_input))

    def test_context_is_scoped_and_bounded(self):
        results = load_results()
        network = results['meta']['scenario'].iloc[0]
        meta = results['meta'][results['meta']['scenario'] == network]
        incidents = results['incidents'][results['incidents']['scenario'] == network]
        context = workspace_context(meta, incidents, network, 'Overview')
        self.assertIn('not live telemetry', context)
        self.assertIn(f'grouped alerts: {len(meta)}', context)
        self.assertLess(len(context), 14000)
        for other in set(results['meta']['scenario']) - {network}:
            self.assertNotIn(f'"scenario":"{other}"', context)

    def test_backend_output_folder_can_be_selected(self):
        data_dir = Path(__file__).resolve().parents[2] / 'data'
        status = backend_status(data_dir)
        self.assertTrue(status['ready'])
        self.assertEqual(status['data_dir'], data_dir.resolve())
        results = load_results(data_dir)
        self.assertEqual(len(results['meta']), 99161)

    @patch('backend_client.requests.get')
    def test_service_online_model_missing(self, get):
        get.return_value = Mock(ok=True)
        get.return_value.json.return_value = {'models': []}
        status = backend_status()
        self.assertTrue(status['ollama_online'])
        self.assertFalse(status['model_ready'])

    @patch('blueteam.llm.requests.post')
    def test_stream_error_closes_response(self, post):
        response = post.return_value
        response.iter_lines.return_value = [b'{"message":{"content":"Hello"}}', b'{"error":"model failed"}']
        stream = llm.chat([], stream=True)
        self.assertEqual(next(stream), 'Hello')
        with self.assertRaisesRegex(RuntimeError, 'model failed'):
            next(stream)
        response.close.assert_called_once()

    @patch('backend_client.ask_analyst', return_value=iter(['Snapshot needs review.']))
    def test_chat_submit_persists_across_pages(self, ask):
        with patch('backend_client.backend_status', return_value={'ready': True, 'missing': [], 'ollama_online': True, 'model_ready': True, 'model': 'test', 'data_dir': Path('data')}):
            app = AppTest.from_file(str(Path(__file__).resolve().parents[1] / 'app.py'), default_timeout=30).run()
            self.sign_in(app)
            app.toggle(key='assistant_open').set_value(True).run()
            app.text_input[0].set_value('What needs attention?')
            next(b for b in app.button if b.label == 'Ask Lens ↗').click().run()
            self.assertEqual(list(app.exception), [])
            self.assertTrue(ask.called)
            app.radio[0].set_value('Model quality').run()
            self.assertEqual(app.session_state['workspace_chats']['All networks'][-1]['content'], 'Snapshot needs review.')


if __name__ == '__main__':
    unittest.main()
