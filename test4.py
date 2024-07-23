from burp import IBurpExtender, IHttpListener, ITab
from javax.swing import JPanel, JLabel, JTextArea, JScrollPane
from java.awt import BorderLayout

class BurpExtender(IBurpExtender, IHttpListener, ITab):
    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        self.callbacks.setExtensionName("Payload Parameter Appender")
        
        # Create a simple UI
        self.panel = JPanel(BorderLayout())
        self.payloads = JTextArea()
        self.payloads.setLineWrap(True)
        self.payloads.setWrapStyleWord(True)
        scrollPane = JScrollPane(self.payloads)
        self.panel.add(JLabel("Payloads (one per line):"), BorderLayout.NORTH)
        self.panel.add(scrollPane, BorderLayout.CENTER)
        
        # Add our custom tab to Burp's UI
        callbacks.addSuiteTab(self)
        
        # Register ourselves as an HTTP listener
        callbacks.registerHttpListener(self)
    
    def getTabCaption(self):
        return "Payload Appender"
    
    def getUiComponent(self):
        return self.panel

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if messageIsRequest:
            requestInfo = self.helpers.analyzeRequest(messageInfo)
            parameters = requestInfo.getParameters()
            
            # Get the payloads from the UI
            payload_list = self.payloads.getText().strip().split("\n")
            
            for payload in payload_list:
                # Create a new request with each parameter appended with the payload
                new_request = messageInfo.getRequest()
                for parameter in parameters:
                    new_value = parameter.getValue() + payload
                    new_param = self.helpers.buildParameter(parameter.getName(), new_value, parameter.getType())
                    new_request = self.helpers.updateParameter(new_request, new_param)

                # Send the modified request to Repeater
                self.callbacks.sendToRepeater(
                    messageInfo.getHttpService().getHost(),
                    messageInfo.getHttpService().getPort(),
                    messageInfo.getHttpService().getProtocol() == "https",
                    new_request,
                    None
                )

