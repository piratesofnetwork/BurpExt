from burp import IBurpExtender, IHttpListener, IExtensionHelpers
from array import array

class BurpExtender(IBurpExtender, IHttpListener):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._stdout = PrintWriter(callbacks.getStdout(), True)

        callbacks.setExtensionName("Payload Injector")
        callbacks.registerHttpListener(self)

        self.payloads = ["payload1", "payload2", "payload3"]  # Add your payloads here

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if messageIsRequest:
            request = messageInfo.getRequest()
            analyzed_request = self._helpers.analyzeRequest(request)

            parameters = analyzed_request.getParameters()
            for payload in self.payloads:
                for parameter in parameters:
                    new_request = self._helpers.updateParameter(request, 
                                    self._helpers.buildParameter(parameter.getName(), 
                                    parameter.getValue() + payload, parameter.getType()))
                    self._callbacks.sendToRepeater(messageInfo.getHttpService().getHost(),
                        messageInfo.getHttpService().getPort(),
                        messageInfo.getHttpService().getProtocol() == "https",
                        new_request, None)

