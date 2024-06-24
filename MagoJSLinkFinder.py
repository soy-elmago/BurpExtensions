# -*- coding: utf-8 -*-

from burp import IBurpExtender, IScannerCheck, IScanIssue, ITab
from java.io import PrintWriter
from java.net import URL
from java.util import ArrayList
from java.util.regex import Matcher, Pattern
import binascii
import base64
import re
from javax import swing
from java.awt import Font, Color
from threading import Thread
from array import array
from java.awt import EventQueue
from java.lang import Runnable
from thread import start_new_thread
from javax.swing import JFileChooser
from javax.swing.event import DocumentListener

# Using the Runnable class for thread-safety with Swing
class Run(Runnable):
    def __init__(self, runner):
        self.runner = runner

    def run(self):
        self.runner()

# Needed params

JSExclusionList = ['jquery', 'google-analytics', 'gpt.js']

class BurpExtender(IBurpExtender, IScannerCheck, ITab):
    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        self.callbacks = callbacks
        callbacks.setExtensionName("BurpJSLinkFinder")

        callbacks.issueAlert("BurpJSLinkFinder Passive Scanner enabled")

        stdout = PrintWriter(callbacks.getStdout(), True)
        stderr = PrintWriter(callbacks.getStderr(), True)
        callbacks.registerScannerCheck(self)
        self.initUI()
        self.callbacks.addSuiteTab(self)

        print("Burp JS LinkFinder loaded.")
        print("Copyright (c) 2019 Frans Hendrik Botes (mod by elmago)")
        self.originalContent = "Burp JS LinkFinder loaded.\nCopyright (c) 2019 Frans Hendrik Botes (mod by elmago)\n"
        self.detectedLogs = []  # Store the log entries as structured data
        self.outputTxtArea.setText(self.originalContent)

    def initUI(self):
        self.tab = swing.JPanel()

        # UI for Output
        self.outputLabel = swing.JLabel("LinkFinder Log:")
        self.outputLabel.setFont(Font("Tahoma", Font.BOLD, 14))
        self.outputLabel.setForeground(Color(255, 102, 52))

        self.searchLabel = swing.JLabel("Search URL:")
        self.searchLabel.setFont(Font("Tahoma", Font.PLAIN, 12))
        self.searchField = swing.JTextField(15)  # Set the preferred width

        # Add DocumentListener to the search field to enable dynamic filtering
        self.searchField.getDocument().addDocumentListener(SearchDocumentListener(self))

        self.logPane = swing.JScrollPane()
        self.outputTxtArea = swing.JTextArea()
        self.outputTxtArea.setFont(Font("Consolas", Font.PLAIN, 12))
        self.outputTxtArea.setLineWrap(True)
        self.logPane.setViewportView(self.outputTxtArea)

        self.clearBtn = swing.JButton("Clear Log", actionPerformed=self.clearLog)
        self.exportBtn = swing.JButton("Export Log", actionPerformed=self.exportLog)
        self.parentFrm = swing.JFileChooser()

        # Checkbox for filtering by scope
        self.scopeCheckbox = swing.JCheckBox("Show only in-scope results")
        self.scopeCheckbox.addActionListener(self.updateScopeFilter)

        # Layout
        layout = swing.GroupLayout(self.tab)
        layout.setAutoCreateGaps(True)
        layout.setAutoCreateContainerGaps(True)
        self.tab.setLayout(layout)

        layout.setHorizontalGroup(
            layout.createParallelGroup()
                .addComponent(self.outputLabel)
                .addGroup(layout.createSequentialGroup()
                    .addComponent(self.searchLabel)
                    .addComponent(self.searchField)
                    .addComponent(self.scopeCheckbox)
                )
                .addComponent(self.logPane)
                .addGroup(layout.createSequentialGroup()
                    .addComponent(self.clearBtn)
                    .addComponent(self.exportBtn)
                )
        )

        layout.setVerticalGroup(
            layout.createSequentialGroup()
                .addComponent(self.outputLabel)
                .addGroup(layout.createParallelGroup(swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(self.searchLabel)
                    .addComponent(self.searchField)
                    .addComponent(self.scopeCheckbox)
                )
                .addComponent(self.logPane)
                .addGroup(layout.createParallelGroup(swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(self.clearBtn)
                    .addComponent(self.exportBtn)
                )
        )

    def getTabCaption(self):
        return "BurpJSLinkFinder"

    def getUiComponent(self):
        return self.tab

    def clearLog(self, event):
        self.detectedLogs = []  # Reset detected logs
        self.outputTxtArea.setText(self.originalContent)

    def exportLog(self, event):
        chooseFile = JFileChooser()
        ret = chooseFile.showDialog(self.logPane, "Choose file")
        filename = chooseFile.getSelectedFile().getCanonicalPath()
        print("\n" + "Export to: " + filename)
        open(filename, 'w', 0).write(self.outputTxtArea.text)

    def filterLog(self, search_term):
        search_term = search_term.strip().lower()
        if not search_term:
            # Restore the full detected logs if the search field is empty
            filtered_logs = self.detectedLogs[:]
        else:
            filtered_logs = []
            for log_entry in self.detectedLogs:
                url_match = log_entry["url"]
                if search_term in url_match.lower():
                    filtered_logs.append(log_entry)
                else:
                    filtered_paths = [path for path in log_entry["paths"] if search_term in path.lower()]
                    if filtered_paths:
                        filtered_logs.append({"url": url_match, "paths": filtered_paths})

        if self.scopeCheckbox.isSelected():
            filtered_logs = [entry for entry in filtered_logs if self.isUrlInScope(entry["url"])]

        # Show filtered results
        self.outputTxtArea.setText(self.formatLogs(filtered_logs))

    def formatLogs(self, logs):
        formatted_log = ""
        for entry in logs:
            formatted_log += "\n[+] Valid URL found: " + entry["url"]
            for path in entry["paths"]:
                formatted_log += "\n\t" + path
        return formatted_log

    def isUrlInScope(self, url):
        try:
            url_object = URL(url)
            return self.callbacks.isInScope(url_object)
        except Exception as e:
            print("Error parsing URL {}: {}".format(url, e))
        return False

    def doPassiveScan(self, ihrr):
        try:
            urlReq = ihrr.getUrl()
            testString = str(urlReq)
            linkA = linkAnalyse(ihrr, self.helpers)
            # check if JS file
            if ".js" in str(urlReq):
                # Exclude casual JS files
                if any(x in testString for x in JSExclusionList):
                    print("\n" + "[-] URL excluded " + str(urlReq))
                else:
                    log_entry = {"url": str(urlReq), "paths": []}
                    self.detectedLogs.append(log_entry)  # Store log entry

                    issueText = linkA.analyseURL()
                    for counter, issueText in enumerate(issueText):
                        path = str(counter) + ' - ' + issueText['link']
                        self.outputTxtArea.append("\n\t" + path)
                        log_entry["paths"].append(path)

                    self.outputTxtArea.append("\n[+] Valid URL found: " + str(urlReq))

                    issues = ArrayList()
                    issues.add(SRI(ihrr, self.helpers))
                    return issues
        except UnicodeEncodeError:
            print("Error in URL decode.")
        return None

    def consolidateDuplicateIssues(self, isb, isa):
        return -1

    def extensionUnloaded(self):
        print("Burp JS LinkFinder unloaded")
        return

    def updateScopeFilter(self, event):
        # Trigger filter update when the scope checkbox is toggled
        self.filterLog(self.searchField.getText())

class SearchDocumentListener(DocumentListener):
    def __init__(self, extender):
        self.extender = extender

    def insertUpdate(self, e):
        self.updateFilter()

    def removeUpdate(self, e):
        self.updateFilter()

    def changedUpdate(self, e):
        self.updateFilter()

    def updateFilter(self):
        search_term = self.extender.searchField.getText()
        self.extender.filterLog(search_term)

class linkAnalyse():

    def __init__(self, reqres, helpers):
        self.helpers = helpers
        self.reqres = reqres

    regex_str = """
    
      (?:"|')                               # Start newline delimiter
    
      (
        ((?:[a-zA-Z]{1,10}://|//)           # Match a scheme [a-Z]*1-10 or //
        [^"'/]{1,}\.                        # Match a domainname (any character + dot)
        [a-zA-Z]{2,}[^"']{0,})              # The domainextension and/or path
    
        |
    
        ((?:/|\.\./|\./)                    # Start with /,../,./
        [^"'><,;| *()(%%$^/\\\[\]]          # Next character can't be...
        [^"'><,;|()]{1,})                   # Rest of the characters can't be
    
        |
    
        ([a-zA-Z0-9_\-/]{1,}/               # Relative endpoint with /
        [a-zA-Z0-9_\-/]{1,}                 # Resource name
        \.(?:[a-zA-Z]{1,4}|action)          # Rest + extension (length 1-4 or action)
        (?:[\?|/][^"|']{0,}|))              # ? mark with parameters
    
        |
    
        ([a-zA-Z0-9_\-]{1,}                 # filename
        \.(?:php|asp|aspx|jsp|json|
             action|html|js|txt|xml)             # . + extension
        (?:\?[^"|']{0,}|))                  # ? mark with parameters
    
      )
    
      (?:"|')                               # End newline delimiter
    
    """

    def parser_file(self, content, regex_str, mode=1, more_regex=None, no_dup=1):
        regex = re.compile(regex_str, re.VERBOSE)
        items = [{"link": m.group(1)} for m in re.finditer(regex, content)]
        if no_dup:
            # Remove duplication
            all_links = set()
            no_dup_items = []
            for item in items:
                if item["link"] not in all_links:
                    all_links.add(item["link"])
                    no_dup_items.append(item)
            items = no_dup_items

        # Match Regex
        filtered_items = []
        for item in items:
            # Remove other capture groups from regex results
            if more_regex:
                if re.search(more_regex, item["link"]):
                    filtered_items.append(item)
            else:
                filtered_items.append(item)
        return filtered_items

    # Potential for use in the future...
    def threadAnalysis(self):
        thread = Thread(target=self.analyseURL(), args=(session,))
        thread.daemon = True
        thread.start()

    def analyseURL(self):

        endpoints = ""
        mime_type = self.helpers.analyzeResponse(self.reqres.getResponse()).getStatedMimeType()
        if mime_type.lower() == 'script':
            url = self.reqres.getUrl()
            encoded_resp = binascii.b2a_base64(self.reqres.getResponse())
            decoded_resp = base64.b64decode(encoded_resp)
            endpoints = self.parser_file(decoded_resp, self.regex_str)
            return endpoints
        return endpoints


class SRI(IScanIssue, ITab):
    def __init__(self, reqres, helpers):
        self.helpers = helpers
        self.reqres = reqres

    def getHost(self):
        return self.reqres.getHost()

    def getPort(self):
        return self.reqres.getPort()

    def getProtocol(self):
        return self.reqres.getProtocol()

    def getUrl(self):
        return self.reqres.getUrl()

    def getIssueName(self):
        return "Linkfinder Analysed JS files"

    def getIssueType(self):
        return 0x08000000  # See http:#portswigger.net/burp/help/scanner_issuetypes.html

    def getSeverity(self):
        return "Information"  # "High", "Medium", "Low", "Information" or "False positive"

    def getConfidence(self):
        return "Certain"  # "Certain", "Firm" or "Tentative"

    def getIssueBackground(self):
        return str("JS files holds links to other parts of web applications. Refer to TAB for results.")

    def getRemediationBackground(self):
        return "This is an <b>informational</b> finding only.<br>"

    def getIssueDetail(self):
        return str("Burp Scanner has analysed the following JS file for links: <b>"
                   "%s</b><br><br>" % (self.reqres.getUrl().toString()))

    def getRemediationDetail(self):
        return None

    def getHttpMessages(self):
        rra = [self.reqres]
        return rra

    def getHttpService(self):
        return self.reqres.getHttpService()


if __name__ in ('__main__', 'main'):
    EventQueue.invokeLater(Run(BurpExtender))
