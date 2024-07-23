from burp import IBurpExtender, ITab, IScannerCheck, IHttpRequestResponse, IResponseInfo, IHttpService
from burp import IHttpListener, IMessageEditorController
from javax.swing import JPanel, JButton, JTextArea, JLabel, JTextField, JScrollPane, JTable, JTabbedPane, JCheckBox, SwingUtilities
from java.awt import BorderLayout, Color, Dimension
from java.util import ArrayList
import threading
import time

class BurpExtender(IBurpExtender, ITab, IScannerCheck, IHttpListener, IMessageEditorController):
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

        self._sqliCheckBox = JCheckBox("Test SQLi")
        self._sqliCheckBox.setBounds(10, 250, 100, 25)
        self._mainPanel.add(self._sqliCheckBox)

        self._xssCheckBox = JCheckBox("Test XSS")
        self._xssCheckBox.setBounds(120, 250, 100, 25)
        self._mainPanel.add(self._xssCheckBox)
        
        self._sstiCheckBox = JCheckBox("Test SSTI")
        self._sstiCheckBox.setBounds(10, 280, 100, 25)
        self._mainPanel.add(self._sstiCheckBox)

        self._ssiCheckBox = JCheckBox("Test SSI")
        self._ssiCheckBox.setBounds(120, 280, 100, 25)
        self._mainPanel.add(self._ssiCheckBox)
        
        self._ssrfCheckBox = JCheckBox("Test SSRF")
        self._ssrfCheckBox.setBounds(10, 310, 100, 25)
        self._mainPanel.add(self._ssrfCheckBox)

        self._startButton = JButton("Start Testing", actionPerformed=self.startTesting)
        self._startButton.setBounds(10, 340, 150, 30)
        self._mainPanel.add(self._startButton)

        self._logArea = JTextArea()
        self._logScrollPane = JScrollPane(self._logArea)
        self._logScrollPane.setBounds(10, 380, 460, 200)
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
        
        testSQLi = self._sqliCheckBox.isSelected()
        testXSS = self._xssCheckBox.isSelected()
        testSSTI = self._sstiCheckBox.isSelected()
        testSSI = self._ssiCheckBox.isSelected()
        testSSRF = self._ssrfCheckBox.isSelected()
        
        self._testingThread = TestingThread(self._callbacks, self._helpers, self._logArea, sqliPayload, xssPayload, sstiPayload, ssiPayload, ssrfPayload, threads, concurrentRequests, delay, testSQLi, testXSS, testSSTI, testSSI, testSSRF)
        self._testingThread.start()

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if not messageIsRequest:
            self._logRequests.add(messageInfo)
            if self._testingThread and self._testingThread.isAlive():
                self._testingThread.addRequest(messageInfo)
    
    def logRequestResponse(self, requestResponse, testName):
        request_info = self._helpers.analyzeRequest(requestResponse)
        response_info = self._helpers.analyzeResponse(requestResponse.getResponse())
        
        self._logArea.append("Test: " + testName + "\n")
        self._logArea.append("Request:\n")
        self._logArea.append(self._helpers.bytesToString(requestResponse.getRequest()) + "\n\n")
        
        self._logArea.append("Response:\n")
        self._logArea.append(self._helpers.bytesToString(requestResponse.getResponse()) + "\n\n")

    def colorizeRequest(self, requestResponse, color):
        # Implement logic to colorize the request
        pass

class TestingThread(threading.Thread):
    def __init__(self, callbacks, helpers, logArea, sqliPayload, xssPayload, sstiPayload, ssiPayload, ssrfPayload, threads, concurrentRequests, delay, testSQLi, testXSS, testSSTI, testSSI, testSSRF):
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
