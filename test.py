from burp import IBurpExtender, IHttpListener, IExtensionHelpers
from java.io import PrintWriter

class BurpExtender(IBurpExtender, IHttpListener):
    
    def registerExtenderCallbacks(self, callbacks):
        # Keep a reference to our callbacks object
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()

        # Set our extension name
        callbacks.setExtensionName("Parameter Payload Appender")

        # Obtain our output stream
        self._stdout = PrintWriter(callbacks.getStdout(), True)

        # Register ourselves as an HTTP listener
        callbacks.registerHttpListener(self)

        # Define payloads
        self.payloads = ["payload1", "payload2", "payload3"]

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if messageIsRequest:
            requestInfo = self._helpers.analyzeRequest(messageInfo)
            parameters = requestInfo.getParameters()

            for payload in self.payloads:
                for parameter in parameters:
                    modifiedParameters = list(parameters)
                    for i in range(len(modifiedParameters)):
                        if modifiedParameters[i].getType() == parameter.getType() and modifiedParameters[i].getName() == parameter.getName():
                            newParam = self._helpers.buildParameter(
                                parameter.getName(),
                                parameter.getValue() + payload,
                                parameter.getType()
                            )
                            modifiedParameters[i] = newParam

                    # Rebuild the request with modified parameters
                    modifiedRequest = self._helpers.updateParameter(
                        messageInfo.getRequest(),
                        modifiedParameters[0]
                    )

                    for param in modifiedParameters[1:]:
                        modifiedRequest = self._helpers.updateParameter(modifiedRequest, param)

                    # Send the modified request to the Repeater
                    self._callbacks.sendToRepeater(
                        messageInfo.getHttpService().getHost(),
                        messageInfo.getHttpService().getPort(),
                        messageInfo.getHttpService().getProtocol() == "https",
                        modifiedRequest,
                        "Modified with payload: " + payload
                    )
                    self._stdout.println("Sent modified request with payload: " + payload)

