# -*- coding: utf-8 -*-
from burp import IBurpExtender, IMessageEditorTabFactory, IMessageEditorTab
from java.util import List, ArrayList
from javax.swing import JPanel, JLabel, ImageIcon
from java.awt import BorderLayout
from javax.imageio import ImageIO
from java.io import ByteArrayInputStream
import base64
import re

class BurpExtender(IBurpExtender, IMessageEditorTabFactory):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Decoded b64 Image Viewer")
        callbacks.registerMessageEditorTabFactory(self)
        print("[+] Extension loaded: Decoded b64 Image Viewer by El Mago @soyel_mago")

    def createNewInstance(self, controller, editable):
        return DecodedImageTab(self._callbacks, self._helpers, controller, editable)

class DecodedImageTab(IMessageEditorTab):
    def __init__(self, callbacks, helpers, controller, editable):
        self._helpers = helpers
        self._editable = editable
        self._tab = JPanel(BorderLayout())
        self._label = JLabel()
        self._tab.add(self._label, BorderLayout.CENTER)
        self._current_message = None

    def getTabCaption(self):
        return "Decoded b64 Image"

    def getUiComponent(self):
        return self._tab

    def isEnabled(self, content, isRequest):
        if isRequest or content is None:
            return False
        try:
            text = self._helpers.bytesToString(content)
            return "data:image" in text and "base64," in text
        except:
            return False

    def setMessage(self, content, isRequest):
        if content is None or isRequest:
            self._label.setIcon(None)
            self._label.setText("")
            self._current_message = None
            return

        text = self._helpers.bytesToString(content)
        match = re.search(r"data:image/[^;]+;base64,([a-zA-Z0-9+/=]+)", text)
        if match:
            try:
                b64_data = match.group(1)
                image_bytes = base64.b64decode(b64_data)
                bais = ByteArrayInputStream(image_bytes)
                buffered_image = ImageIO.read(bais)
                if buffered_image is not None:
                    icon = ImageIcon(buffered_image)
                    self._label.setIcon(icon)
                    self._label.setText("")
                else:
                    self._label.setIcon(None)
                    self._label.setText("Unable to decode image.")
            except Exception as e:
                self._label.setIcon(None)
                self._label.setText("Error decoding image: " + str(e))
        else:
            self._label.setIcon(None)
            self._label.setText("No base64 image found.")

    def getMessage(self):
        return self._current_message

    def isModified(self):
        return False

    def getSelectedData(self):
        return None
