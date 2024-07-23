from burp import IBurpExtender, ITab, IScannerCheck, IHttpRequestResponse, IResponseInfo, IHttpService
from burp import IHttpListener
from javax.swing import JPanel, JButton, JTextArea, JLabel, JTextField, JScrollPane, JTable, JTabbedPane, JComboBox, SwingUtilities
from java.awt import BorderLayout, Color
from java.util import ArrayList
import threading
import time

class BurpExtender(IBurpExtender, ITab, IScannerCheck, IHttpListener):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._callbacks.setExtensionName("Manual Security Tester")
        self._callbacks.registerScannerCheck(self)
        self._callbacks.registerHttpListener(self)
        
        self._panel = JPanel(BorderLayout())
        self._tabs = JTabbedPane()

        self._panel.add(self._tabs, BorderLayout.CENTER)

        self._createUI()
        
        callbacks.addSuiteTab(self)
        
        self._logRequests = ArrayList()

    def _createUI(self):
        self._mainPanel = JPanel()
        self._mainPanel.setLayout(None)

        self._sqliPayloadLabel = JLabel("SQLi Payload:")
        self._sqliPayloadLabel.setBounds(10, 10, 100, 25)
        self._mainPanel.add(self._sqliPayloadLabel)

        self._sqliPayloadText = JTextField()
        self._sqliPayloadText.setBounds(120, 10, 300, 25)
        self._mainPanel.add(self._sqliPayloadText)

        self._xssPayloadLabel = JLabel("XSS Payload:")
        self._xssPayloadLabel.setBounds(10, 40, 100, 25)
        self._mainPanel.add(self._xssPayloadLabel)

        self._xssPayloadText = JTextField()
        self._xssPayloadText.setBounds(120, 40, 300, 25)
        self._mainPanel.add(self._xssPayloadText)
        
        self._sstiPayloadLabel = JLabel("SSTI Payload:")
        self._sstiPayloadLabel.setBounds(10, 70, 100, 25)
        self._mainPanel.add(self._sstiPayloadLabel)

        self._sstiPayloadText = JTextField()
        self._sstiPayloadText.setBounds(120, 70, 300, 25)
        self._mainPanel.add(self._sstiPayloadText)
        
        self._ssiPayloadLabel = JLabel("SSI Payload:")
        self._ssiPayloadLabel.setBounds(10, 100, 100, 25)
        self._mainPanel.add(self._ssiPayloadLabel)

        self._ssiPayloadText = JTextField()
        self._ssiPayloadText.setBounds(120, 100, 300, 25)
        self._mainPanel.add(self._ssiPayloadText)
        
        self._ssrfPayloadLabel = JLabel("SSRF Payload:")
        self._ssrfPayloadLabel.setBounds(10, 130, 100, 25)
        self._mainPanel.add(self._ssrfPayloadLabel)

        self._ssrfPayloadText = JTextField()
        self._ssrfPayloadText.setBounds(120, 130, 300, 25)
        self._mainPanel.add(self._ssrfPayloadText)

        self._threadsLabel = JLabel("Threads:")
        self._threadsLabel.setBounds(10, 160, 100, 25)
        self._mainPanel.add(self._threadsLabel)

        self._threadsText = JTextField("5")
        self._threadsText.setBounds(120, 160, 50, 25)
        self._mainPanel.add(self._threadsText)
        
        self._concurrentRequestsLabel = JLabel("Concurrent Requests:")
        self._concurrentRequestsLabel.setBounds(10, 190, 150, 25)
        self._mainPanel.add(self._concurrentRequestsLabel)

        self._concurrentRequestsText = JTextField("10")
        self._concurrentRequestsText.setBounds(170, 190, 50, 25)
        self._mainPanel.add(self._concurrentRequestsText)
        
        self._delayLabel = JLabel("Delay (ms):")
        self._delayLabel.setBounds(10, 220, 100, 25)
        self._mainPanel.add(self._delayLabel)

        self._delayText = JTextField("1000")
        self._delayText.setBounds(120, 220, 50, 25)
        self._mainPanel.add(self._delayText)

        self._startButton = JButton("Start Testing", actionPerformed=self.startTesting)
        self._startButton.setBounds(10, 250, 150, 30)
        self._mainPanel.add(self._startButton)

        self._logArea = JTextArea()
        self._logScrollPane = JScrollPane(self._logArea)
        self._logScrollPane.setBounds(10, 290, 460, 200)
        self._mainPanel.add(self._logScrollPane)

        self._tabs.addTab("Manual Security Tester", self._mainPanel)
    
    def getTabCaption(self):
        return "Security Tester"
    
    def getUiComponent(self):
        return self._panel

    def startTesting(self, event):
        sqliPayload = self._sqliPayloadText.getText()
        xssPayload = self._xssPayloadText.getText()
        sstiPayload = self._sstiPayloadText.getText()
        ssiPayload = self._ssiPayloadText.getText()
        ssrfPayload = self._ssrfPayloadText.getText()
        
        threads = int(self._threadsText.getText())
        concurrentRequests = int(self._concurrentRequestsText.getText())
        delay = int(self._delayText.getText())
        
        self._testingThread = TestingThread(self._callbacks, self._helpers, self._logArea, sqliPayload, xssPayload, sstiPayload, ssiPayload, ssrfPayload, threads, concurrentRequests, delay)
        self._testingThread.start()

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if not messageIsRequest:
            self._logRequests.add(messageInfo)
            if self._testingThread and self._testingThread.isAlive():
                self._testingThread.addRequest(messageInfo)
    
    def logRequestResponse(self, requestResponse):
        request_info = self._helpers.analyzeRequest(requestResponse)
        response_info = self._helpers.analyzeResponse(requestResponse.getResponse())
        
        self._logArea.append("Request:\n")
        self._logArea.append(self._helpers.bytesToString(requestResponse.getRequest()) + "\n\n")
        
        self._logArea.append("Response:\n")
        self._logArea.append(self._helpers.bytesToString(requestResponse.getResponse()) + "\n\n")

    def colorizeRequest(self, requestResponse, color):
        # Implement logic to colorize the request
        pass

class TestingThread(threading.Thread):
    def __init__(self, callbacks, helpers, logArea, sqliPayload, xssPayload, sstiPayload, ssiPayload, ssrfPayload, threads, concurrentRequests, delay):
        threading.Thread.__init__(self)
        self.callbacks = callbacks
        self.helpers = helpers
        self.logArea = logArea
        self.sqliPayload = sqliPayload
        self.xssPayload = xssPayload
        self.sstiPayload = sstiPayload
        self.ssiPayload = ssiPayload
        self.ssrfPayload = ssrfPayload
        self.threads = threads
        self.concurrentRequests = concurrentRequests
        self.delay = delay
        self.requestQueue = ArrayList()

    def run(self):
        while not self.requestQueue.isEmpty():
            requestResponse = self.requestQueue.remove(0)
            self.testRequestResponse(requestResponse)
            time.sleep(self.delay / 1000)

    def addRequest(self, requestResponse):
        self.requestQueue.add(requestResponse)

    def testRequestResponse(self, requestResponse):
        requestInfo = self.helpers.analyzeRequest(requestResponse)
        params = requestInfo.getParameters()
        
        for param in params:
            if param.getType() == param.PARAM_URL or param.PARAM_BODY:
                paramName = param.getName()
                paramValue = param.getValue()
                
                # SQLi Testing
                modifiedRequest = self.modifyParameter(requestResponse, param, self.sqliPayload)
                if self.testPayload(modifiedRequest):
                    self.logIssue("SQL Injection", requestResponse, paramName)
                
                # XSS Testing
                modifiedRequest = self.modifyParameter(requestResponse, param, self.xssPayload)
                if self.testPayload(modifiedRequest):
                    self.logIssue("Cross-Site Scripting", requestResponse, paramName)
                
                # SSTI Testing
                modifiedRequest = self.modifyParameter(requestResponse, param, self.sstiPayload)
                if self.testPayload(modifiedRequest):
                    self.logIssue("Server-Side Template Injection", requestResponse, paramName)
                
                # SSI Testing
                modifiedRequest = self.modifyParameter(requestResponse, param, self.ssiPayload)
                if self.testPayload(modifiedRequest):
                    self.logIssue("Server-Side Includes Injection", requestResponse, paramName)
                
                # SSRF Testing
                modifiedRequest = self.modifyParameter(requestResponse, param, self.ssrfPayload)
               
