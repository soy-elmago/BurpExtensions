# -*- coding: utf-8 -*-
from burp import IBurpExtender, IMessageEditorTabFactory, IMessageEditorTab
import json
from java.net import URLDecoder, URLEncoder

class BurpExtender(IBurpExtender):
    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Burp Suite Lightning II (mod by ElMago)")

        callbacks.printOutput("Burp Suite Lightning II (mod by ElMago)")
        callbacks.printOutput("Forked from https://github.com/salesforce/lightning-burp")

        callbacks.registerMessageEditorTabFactory(AuraJSONTabFactory(self.callbacks, "message", "Aura Message"))
        callbacks.registerMessageEditorTabFactory(AuraJSONTabFactory(self.callbacks, "aura.context", "Aura Context"))

class AuraJSONTabFactory(IMessageEditorTabFactory):
    def __init__(self, callbacks, key, tab_caption):
        self.callbacks = callbacks
        self.key = key
        self.tab_caption = tab_caption

    def createNewInstance(self, controller, editable):
        return AuraJSONTab(self.callbacks, controller, editable, self.key, self.tab_caption)

class AuraJSONTab(IMessageEditorTab):
    def __init__(self, callbacks, controller, editable, key, tab_caption):
        self.callbacks = callbacks
        self.controller = controller
        self.editable = editable
        self.key = key
        self.tab_caption = tab_caption
        self.helpers = callbacks.getHelpers()
        self.text_editor = callbacks.createTextEditor()
        self.current_content = None
        self.original_message = None

    def getTabCaption(self):
        return self.tab_caption

    def isEnabled(self, content, is_request):
        if content is None:
            return False
        request_info = self.helpers.analyzeRequest(content)
        parameters = request_info.getParameters()
        for param in parameters:
            if param.getName() == self.key:
                return True
        return False

    def getUiComponent(self):
        return self.text_editor.getComponent()

    def setMessage(self, content, is_request):
        if content is None:
            self.text_editor.setText(None)
            return
        
        request_info = self.helpers.analyzeRequest(content)
        parameters = request_info.getParameters()
        for param in parameters:
            if param.getName() == self.key:
                decoded_message = URLDecoder.decode(param.getValue(), "UTF-8")
                try:
                    formatted_json = json.dumps(json.loads(decoded_message), indent=4)
                except json.JSONDecodeError:
                    formatted_json = decoded_message
                self.text_editor.setText(formatted_json.encode('utf-8'))
                self.current_content = content
                self.original_message = param.getValue()
                break

    def getMessage(self):
        if not self.isModified():
            return self.current_content

        modified_json = self.text_editor.getText().tostring()

        try:
            json.loads(modified_json)
        except json.JSONDecodeError:
            return self.current_content

        request_info = self.helpers.analyzeRequest(self.current_content)
        parameters = request_info.getParameters()
        
        for param in parameters:
            if param.getName() == self.key:
                encoded_message = URLEncoder.encode(modified_json, "UTF-8")
                updated_request = self.helpers.updateParameter(self.current_content, 
                                                              self.helpers.buildParameter(param.getName(), 
                                                                                          encoded_message, 
                                                                                          param.getType()))
                return updated_request
        
        return self.current_content

    def isModified(self):
        return self.text_editor.isTextModified()

    def getSelectedData(self):
        return self.text_editor.getSelectedText()
