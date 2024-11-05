# -*- coding: utf-8 -*-
from burp import IBurpExtender, IContextMenuFactory
from javax.swing import JMenuItem
from java.util import ArrayList
from java.io import PrintWriter

class BurpExtender(IBurpExtender, IContextMenuFactory):

    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Mercado Libre/Mercado Pago Request Cleaner")
        self.stdout = PrintWriter(callbacks.getStdout(), True)
        
        callbacks.registerContextMenuFactory(self)
        self.stdout.println("Mercado Libre/Mercado Pago Request Cleaner by @soyelmago")

    def createMenuItems(self, invocation):
        menu = ArrayList()
        menu_item = JMenuItem("Clean MercadoLibre/MercadoPago Headers", actionPerformed=lambda x: self.clean_headers(invocation))
        menu.add(menu_item)
        return menu
    
    def clean_headers(self, invocation):
        for messageInfo in invocation.getSelectedMessages():
            self.clean_request_headers(messageInfo)
        self.stdout.println("Headers cleaned for selected MercadoLibre/MercadoPago requests")

    def clean_request_headers(self, messageInfo):
        request = messageInfo.getRequest()
        analyzedRequest = self.helpers.analyzeRequest(request)
        headers = analyzedRequest.getHeaders()
        body = request[analyzedRequest.getBodyOffset():]

        initial_line = headers[0]
        new_headers = [initial_line]
        
        host_header = None
        te_header = None
        user_agent_header = None
        nat_value = None
        ssid_value = None
        orguseridp_value = None
        
        url = self.helpers.analyzeRequest(messageInfo).getUrl()
        if "mercadolibre.com" not in url.getHost() and "mercadopago.com" not in url.getHost():
            return

        for header in headers:
            if header.startswith("Host:"):
                host_header = header
            elif header.startswith("Te:"):
                te_header = header
            elif header.startswith("User-Agent:"):
                user_agent_header = header
            elif header.startswith("Cookie:"):
                cookies = header.split("; ")
                nat_value = next((cookie for cookie in cookies if cookie.startswith("nat=")), None)
                orguseridp_value = next((cookie for cookie in cookies if cookie.startswith("orguseridp=")), None)
                ssid_value = next((cookie for cookie in cookies if cookie.startswith("ssid=")), None)
        
        cookie_header = "Cookie: "
        cookie_elements = []
        if nat_value:
            cookie_elements.append(nat_value)
        if orguseridp_value:
            cookie_elements.append(orguseridp_value)
        if ssid_value:
            cookie_elements.append(ssid_value)
        if cookie_elements:
            cookie_header += "; ".join(cookie_elements)
            new_headers.append(cookie_header)

        for header in headers:
            if header.startswith("Origin:") or header.startswith("Content-Type:"):
                new_headers.append(header)
        
        if host_header:
            new_headers.append(host_header)
        if te_header:
            new_headers.append(te_header)
        if user_agent_header:
            new_headers.append(user_agent_header)

        new_request = self.helpers.buildHttpMessage(new_headers, body)
        messageInfo.setRequest(new_request)
