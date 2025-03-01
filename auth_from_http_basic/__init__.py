# -*- coding: utf-8 -*-
##############################################################################
#
#    OpenERP/Odoo, Open Source Management Solution
#    Copyright (C) 2024 Therp BV, Odoo Community Association (OCA)
#
##############################################################################

from odoo.addons.web.controllers import main as web_main
from odoo.http import request, WebRequest, JsonRequest
import base64
import logging

_logger = logging.getLogger(__name__)

old_init = WebRequest.init


def init(self, params):
    """Intercepta requisições e executa autenticação via Basic Auth"""
    old_init(self, params)

    if "Authorization" in self.httprequest.headers and not self.session._uid:
        auth_header = self.httprequest.headers.get("Authorization")
        
        if auth_header.startswith("Basic "):
            try:
                # Decodifica o cabeçalho Basic Auth
                auth_decoded = base64.b64decode(auth_header[6:]).decode("utf-8")
                username, password = auth_decoded.split(":", 1)

                # Busca o usuário no Odoo
                user = request.env["res.users"].sudo().search(
                    [("login", "=", username)], limit=1
                )

                # Se encontrar, autentica no Odoo
                if user and user._check_credentials(password, "password"):
                    request.session.authenticate(
                        request.env.cr.dbname, username, password
                    )
                else:
                    _logger.warning(f"Falha na autenticação de {username}")
            except Exception as e:
                _logger.error(f"Erro na autenticação Basic Auth: {e}")


WebRequest.init = init


old_dispatch = JsonRequest.dispatch


def dispatch(self, method):
    """Garante que a sessão é encerrada corretamente ao deslogar"""
    response = old_dispatch(self, method)

    if method.__name__ == "destroy" and hasattr(web_main, "Session"):
        response.status = "301 logout"
        response.headers.add("Location", self.httprequest.url.replace("://", "://logout@"))

    return response


JsonRequest.dispatch = dispatch