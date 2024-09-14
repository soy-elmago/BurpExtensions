from burp import IBurpExtender, IContextMenuFactory, IContextMenuInvocation
from javax.swing import JMenuItem
from java.util import ArrayList
import re

class BurpExtender(IBurpExtender, IContextMenuFactory):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Facebook Request Cleaner")
        callbacks.registerContextMenuFactory(self)
        
        # Output to Burp's console
        self._stdout = callbacks.getStdout()
        self._stderr = callbacks.getStderr()
        self._stdout.println("Facebook Request Cleaner extension loaded")
        
    def createMenuItems(self, invocation):
        self.context = invocation
        menu_list = ArrayList()
        
        # Add the menu item only if the request is from Facebook
        if self.context.getInvocationContext() == IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST:
            messages = self.context.getSelectedMessages()
            if messages and "facebook.com" in self._helpers.analyzeRequest(messages[0]).getUrl().getHost():
                menu_list.add(JMenuItem("Clean Facebook Request", actionPerformed=self.clean_facebook_request))
        
        return menu_list
    
    def clean_facebook_request(self, event):
        messages = self.context.getSelectedMessages()
        
        for message in messages:
            request_info = self._helpers.analyzeRequest(message)
            headers = list(request_info.getHeaders())
            body = message.getRequest()[request_info.getBodyOffset():].tostring()
            
            # Step 1: Remove unnecessary cookies
            headers = self.clean_cookies(headers)
            
            # Step 2: Remove unnecessary parameters from the body
            new_body = self.clean_parameters(body)
            
            # Rebuild the request with the cleaned headers and body
            new_message = self._helpers.buildHttpMessage(headers, new_body)
            message.setRequest(new_message)
            
            self._stdout.println("Facebook request cleaned")
    
    def clean_cookies(self, headers):
        clean_headers = []
        for header in headers:
            if header.startswith("Cookie:"):
                cookie_header = header
                # Split cookies
                cookies = cookie_header[len("Cookie: "):].split("; ")
                clean_cookies = [cookie for cookie in cookies if not re.match(r"^(fr|sb|datr|ps_n|ps_l|wd|presence|usida|.*)=.*$", cookie)]
                # Always keep xs and c_user cookies
                clean_cookies.extend([cookie for cookie in cookies if re.match(r"^(xs|c_user)=.*$", cookie)])
                clean_headers.append("Cookie: " + "; ".join(clean_cookies))
            else:
                clean_headers.append(header)
        return clean_headers

    def clean_parameters(self, body):
        # Define parameters to remove
        params_to_remove = [
            "__aaid", "__dyn","__user", "av", "__usid", "__a", "__req", "__hs", "dpr",
            "__ccg", "__rev", "__s", "__csr", "__hsi", "__comet_req", "jazoest",
            "lsd", "__spin_r", "__spin_b", "__spin_t", "fb_api_caller_class",
            "fb_api_req_friendly_name", "server_timestamps"
        ]

        # Keep parameters intact
        params_to_keep = ["fb_dtsg", "variables", "doc_id"]

        # Split body into parameters and filter out unwanted ones
        params = body.split("&")
        cleaned_params = []
        for param in params:
            key, value = param.split("=", 1)
            if key not in params_to_remove or key in params_to_keep:
                cleaned_params.append(param)

        # Reconstruct the cleaned body
        new_body = "&".join(cleaned_params)
        return new_body.encode('utf-8')

