import unittest
from unittest.mock import patch, Mock
import io
import sys

# Importa o módulo que será testado
import validador_url

class TestURLValidator(unittest.TestCase):

    def setUp(self):
        # Redireciona stdout e stderr para capturar prints
        self.held_stdout = sys.stdout
        self.held_stderr = sys.stderr
        sys.stdout = self.captured_stdout = io.StringIO()
        sys.stderr = self.captured_stderr = io.StringIO()

    def tearDown(self):
        # Restaura stdout e stderr
        sys.stdout = self.held_stdout
        sys.stderr = self.held_stderr

    # --- Testes de validação de URL ---
    def test_is_valid_url(self):
        self.assertTrue(validador_url.is_valid_url("http://example.com"))
        self.assertFalse(validador_url.is_valid_url("not a url"))

    # --- Testes para VirusTotal ---
    @patch('validador_url.VT_API_KEY', 'fake_vt_key')
    @patch('requests.get')
    def test_virustotal_malicious(self, mock_get):
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {'data': {'attributes': {'last_analysis_stats': {'malicious': 5, 'suspicious': 1}}}}
        mock_get.return_value = mock_response

        validador_url.verificar_com_virustotal("http://sitemalicioso.com")
        output = self.captured_stdout.getvalue()
        self.assertIn("Relatório VirusTotal", output)
        self.assertIn("Resultado: PERIGOSO", output)

    # --- Testes para Google Safe Browsing ---
    @patch('validador_url.GSB_API_KEY', 'fake_gsb_key')
    @patch('requests.post')
    def test_google_safe_browsing_malicious(self, mock_post):
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {'matches': [{'threatType': 'SOCIAL_ENGINEERING'}]}
        mock_post.return_value = mock_response

        validador_url.verificar_com_google("http://phishing.com")
        output = self.captured_stdout.getvalue()
        self.assertIn("Relatório Google Safe Browsing", output)
        self.assertIn("Ameaça encontrada: SOCIAL_ENGINEERING", output)
        self.assertIn("Resultado: PERIGOSO", output)

    @patch('validador_url.GSB_API_KEY', 'fake_gsb_key')
    @patch('requests.post')
    def test_google_safe_browsing_safe(self, mock_post):
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {}  # Resposta vazia significa seguro
        mock_post.return_value = mock_response

        validador_url.verificar_com_google("http://siteseguro.com")
        output = self.captured_stdout.getvalue()
        self.assertIn("Relatório Google Safe Browsing", output)
        self.assertIn("Nenhuma ameaça encontrada", output)
        self.assertIn("Resultado: SEGURO (segundo o Google)", output)

    # --- Teste de orquestração ---
    @patch('validador_url.verificar_com_virustotal')
    @patch('validador_url.verificar_com_google')
    def test_analisar_url_chama_ambos_servicos(self, mock_google_check, mock_vt_check):
        validador_url.analisar_url("http://qualquerurl.com")
        
        # Verifica se cada função de verificação foi chamada uma vez
        mock_vt_check.assert_called_once_with("http://qualquerurl.com")
        mock_google_check.assert_called_once_with("http://qualquerurl.com")

    # --- Teste de validação de chaves ---
    @patch('validador_url.VT_API_KEY', None)
    @patch('validador_url.GSB_API_KEY', None)
    def test_validate_api_keys_missing(self):
        validador_url._validate_api_keys_for_cli()
        output = self.captured_stderr.getvalue()
        self.assertIn("Aviso: Chave da API do VirusTotal não configurada", output)
        self.assertIn("Aviso: Chave da API do Google Safe Browsing não configurada", output)


if __name__ == '__main__':
    unittest.main(verbosity=2)
