package org.openhab.binding.sip.shootist;

import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.ListIterator;
import java.util.Properties;
import java.util.TimerTask;

import javax.sip.ClientTransaction;
import javax.sip.Dialog;
import javax.sip.DialogTerminatedEvent;
import javax.sip.IOExceptionEvent;
import javax.sip.ListeningPoint;
import javax.sip.PeerUnavailableException;
import javax.sip.RequestEvent;
import javax.sip.ResponseEvent;
import javax.sip.ServerTransaction;
import javax.sip.SipFactory;
import javax.sip.SipListener;
import javax.sip.SipProvider;
import javax.sip.SipStack;
import javax.sip.TransactionTerminatedEvent;
import javax.sip.address.Address;
import javax.sip.address.AddressFactory;
import javax.sip.address.SipURI;
import javax.sip.address.URI;
import javax.sip.header.AllowHeader;
import javax.sip.header.AuthorizationHeader;
import javax.sip.header.CSeqHeader;
import javax.sip.header.CallIdHeader;
import javax.sip.header.ContactHeader;
import javax.sip.header.ContentTypeHeader;
import javax.sip.header.FromHeader;
import javax.sip.header.Header;
import javax.sip.header.HeaderFactory;
import javax.sip.header.MaxForwardsHeader;
import javax.sip.header.RequireHeader;
import javax.sip.header.RouteHeader;
import javax.sip.header.ToHeader;
import javax.sip.header.ViaHeader;
import javax.sip.header.WWWAuthenticateHeader;
import javax.sip.message.MessageFactory;
import javax.sip.message.Request;
import javax.sip.message.Response;

import org.openhab.binding.sip.handler.sipHandler;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import gov.nist.javax.sip.clientauthutils.DigestServerAuthenticationHelper;
import gov.nist.javax.sip.header.Expires;
import gov.nist.javax.sip.header.HeaderFactoryImpl;
import gov.nist.javax.sip.header.ims.SecurityServerHeader;
import gov.nist.javax.sip.header.ims.SecurityVerifyHeader;
import gov.nist.javax.sip.header.ims.SecurityVerifyList;

public class shootist implements SipListener {

    private final Logger logger = LoggerFactory.getLogger(shootist.class);

    private static SipProvider sipProvider;

    private static AddressFactory addressFactory;

    private static MessageFactory messageFactory;

    private static HeaderFactory headerFactory;

    private static SipStack sipStack;

    private ContactHeader contactHeader;

    private ListeningPoint udpListeningPoint;

    private ClientTransaction inviteTid;

    private Dialog dialog;

    private boolean byeTaskRunning;

    private String name;

    class ByeTask extends TimerTask {
        Dialog dialog;

        public ByeTask(Dialog dialog) {
            this.dialog = dialog;
        }

        @Override
        public void run() {
            try {
                Request byeRequest = this.dialog.createRequest(Request.BYE);
                ClientTransaction ct = sipProvider.getNewClientTransaction(byeRequest);
                dialog.sendRequest(ct);
            } catch (Exception ex) {
                ex.printStackTrace();
            }
        }
    }

    @Override
    public void processRequest(RequestEvent requestReceivedEvent) {
        Request request = requestReceivedEvent.getRequest();
        ServerTransaction serverTransactionId = requestReceivedEvent.getServerTransaction();

        logger.info("\n\nRequest " + request.getMethod() + " received at " + sipStack.getStackName()
                + " with server transaction id " + serverTransactionId);

        // We are the UAC so the only request we get is the BYE.
        if (request.getMethod().equals(Request.BYE)) {
            processBye(request, serverTransactionId);
        }

    }

    public void processBye(Request request, ServerTransaction serverTransactionId) {

        try {
            logger.info("shootist:  got a bye .");
            if (serverTransactionId == null) {
                logger.info("shootist:  null TID.");
                return;
            }
            Dialog dialog = serverTransactionId.getDialog();
            logger.info("Dialog State = " + dialog.getState());
            Response response = messageFactory.createResponse(200, request);
            serverTransactionId.sendResponse(response);
            logger.info("shootist:  Sending OK.");
            logger.info("Dialog State = " + dialog.getState());

        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }

    public void processInviteOK(Response ok, ClientTransaction ct) {

        HeaderFactoryImpl headerFactoryImpl = (HeaderFactoryImpl) headerFactory;

        try {

            RequireHeader require = null;
            String requireOptionTags = new String();
            ListIterator li = ok.getHeaders(RequireHeader.NAME);
            if (li != null) {
                try {
                    while (li.hasNext()) {
                        require = (RequireHeader) li.next();
                        requireOptionTags = requireOptionTags.concat(require.getOptionTag()).concat(" ");
                    }
                } catch (Exception ex) {
                    logger.info("\n(!) Exception getting Require header! - " + ex);
                }
            }

            // this is only to illustrate the usage of this headers
            // send Security-Verify (based on Security-Server) if Require: sec-agree
            SecurityVerifyList secVerifyList = null;
            if (requireOptionTags.indexOf("sec-agree") != -1) {
                ListIterator secServerReceived = ok.getHeaders(SecurityServerHeader.NAME);
                if (secServerReceived != null && secServerReceived.hasNext()) {
                    logger.info(".: Security-Server received: ");

                    while (secServerReceived.hasNext()) {
                        SecurityServerHeader security = null;
                        try {
                            security = (SecurityServerHeader) secServerReceived.next();
                        } catch (Exception ex) {
                            logger.info("(!) Exception getting Security-Server header : " + ex);
                        }

                        try {
                            Iterator parameters = security.getParameterNames();
                            SecurityVerifyHeader newSecVerify = headerFactoryImpl.createSecurityVerifyHeader();
                            newSecVerify.setSecurityMechanism(security.getSecurityMechanism());
                            while (parameters.hasNext()) {
                                String paramName = (String) parameters.next();
                                newSecVerify.setParameter(paramName, security.getParameter(paramName));
                            }

                            logger.info("   - " + security.toString());

                        } catch (Exception ex) {
                            logger.info("(!) Exception setting the security agreement!" + ex);
                            ex.getStackTrace();
                        }

                    }
                }
                logger.info(".: Security-Verify built and added to response...");
            }

            CSeqHeader cseq = (CSeqHeader) ok.getHeader(CSeqHeader.NAME);
            ackRequest = dialog.createAck(cseq.getSeqNumber());

            if (secVerifyList != null && !secVerifyList.isEmpty()) {
                RequireHeader requireSecAgree = headerFactory.createRequireHeader("sec-agree");
                ackRequest.setHeader(requireSecAgree);

                ackRequest.setHeader(secVerifyList);
            }

            logger.info("Sending ACK");
            dialog.sendAck(ackRequest);

        } catch (Exception ex) {
            logger.info("(!) Exception sending ACK to 200 OK " + "response to INVITE : " + ex);
        }
    }

    // Save the created ACK request, to respond to retransmitted 2xx
    private Request ackRequest;
    public int invco = 1;
    CallIdHeader callID = null;

    @Override
    public void processResponse(ResponseEvent responseReceivedEvent) {
        logger.info("Got a response");
        Response response = responseReceivedEvent.getResponse();
        ClientTransaction tid = responseReceivedEvent.getClientTransaction();
        CSeqHeader cseq = (CSeqHeader) response.getHeader(CSeqHeader.NAME);
        logger.info("Response received : Status Code = " + response.getStatusCode() + " " + cseq);
        if (response.getStatusCode() == Response.UNAUTHORIZED) {
            try {
                invco++;
                SipFactory sipFactory = null;
                sipFactory = SipFactory.getInstance();
                sipFactory.setPathName("gov.nist");
                String transport = "udp";
                headerFactory = sipFactory.createHeaderFactory();
                addressFactory = sipFactory.createAddressFactory();
                messageFactory = sipFactory.createMessageFactory();

                String fromName = name;
                String fromSipAddress = "open-ims.test";

                String toSipAddress = "open-ims.test";
                String toUser = name;

                // create >From Header
                SipURI fromAddress = addressFactory.createSipURI(fromName, fromSipAddress);
                Address fromNameAddress = addressFactory.createAddress(fromAddress);
                // fromNameAddress.setDisplayName(fromDisplayName);
                FromHeader fromHeader = headerFactory.createFromHeader(fromNameAddress, null);

                // create To Header
                SipURI toAddress = addressFactory.createSipURI(toUser, toSipAddress);
                Address toNameAddress = addressFactory.createAddress(toAddress);
                // toNameAddress.setDisplayName(toDisplayName);
                ToHeader toHeader = headerFactory.createToHeader(toNameAddress, null);

                // create Request URI
                // If response is 403 Forbidden - Domain not serviced edit peerHostPort to domain
                URI requestURI = addressFactory.createURI("sip:" + name + "@open-ims.test"/* peerHostPort */);

                // Create ViaHeader
                ArrayList viaHeaders = new ArrayList();
                ViaHeader viaHeader = headerFactory.createViaHeader("163.17.21.75", 5060, transport, null);

                // add via headers
                viaHeaders.add(viaHeader);

                // Create ContentTypeHeader
                ContentTypeHeader contentTypeHeader = headerFactory.createContentTypeHeader("application", "sdp");

                // Create a new CallId header
                CallIdHeader callIdHeader = callID;

                // Create a new Cseq header
                CSeqHeader cSeqHeader = headerFactory.createCSeqHeader(invco, Request.REGISTER);

                // Create a new MaxForwardsHeader
                MaxForwardsHeader maxForwards = headerFactory.createMaxForwardsHeader(70);

                // Create the request.
                Request request = messageFactory.createRequest(requestURI, Request.REGISTER, callIdHeader, cSeqHeader,
                        fromHeader, toHeader, viaHeaders, maxForwards);

                // route search
                Address routeaddress = addressFactory.createAddress("sip:orig@scscf.open-ims.test:5060;lr");
                RouteHeader routeHeader = shootist.headerFactory.createRouteHeader(routeaddress);
                // request.addHeader(routeHeader);

                // Create contact headers
                String host = "163.17.21.188";
                Header contactH;

                // Create the contact name address.
                SipURI contactURI = addressFactory.createSipURI(fromName, host);
                contactURI.setPort(sipProvider.getListeningPoint(transport).getPort());
                Address contactAddress = addressFactory.createAddress(contactURI);

                contactH = headerFactory.createHeader("Contact", "<sip:" + name + "@" + fromSipAddress + ":" + "5060"
                        + ";transport=udp>;expires=60;+g.oma.sip-im;language=\"en,fr\";+g.3gpp.smsip;+g.oma.sip-im.large-message;audio;+g.3gpp.icsi-ref=\"urn%3Aurn-7%3A3gpp-application.ims.iari.gsma-vs\";+g.3gpp.cs-voice"); // my_add
                contactHeader = headerFactory.createContactHeader(contactAddress);
                contactHeader.setExpires(60);
                contactHeader.setParameter("language", "en,fr");
                request.addHeader(contactH);

                // work-around for IMS header
                HeaderFactoryImpl headerFactoryImpl = new HeaderFactoryImpl();

                AllowHeader allow1 = headerFactory.createAllowHeader(Request.REGISTER);
                request.addHeader(allow1);

                int expires = 60;
                Expires ExpiresHead = (Expires) headerFactory.createExpiresHeader(expires);
                request.addHeader(ExpiresHead);

                // Create the auth info
                AuthorizationHeader authHeader = makeAuthHeader(response, request);
                request.addHeader(authHeader);

                inviteTid = sipProvider.getNewClientTransaction(request);
                inviteTid.sendRequest();
                logger.info(
                        "--------------------------------Sent registar with Auth info--------------------------------");
            } catch (Exception ex) {
                logger.info(ex.getMessage());
                ex.printStackTrace();
            }
        }

    }

    public AuthorizationHeader makeAuthHeader(Response response, Request request) {
        AuthorizationHeader nothing = null;
        try {
            // Authenticate header with challenge we need to reply to
            WWWAuthenticateHeader ah_c = (WWWAuthenticateHeader) response.getHeader(WWWAuthenticateHeader.NAME);

            // Authorization header we will build with response to challenge
            AuthorizationHeader ah_r = headerFactory.createAuthorizationHeader(ah_c.getScheme());

            // assemble data we need to create response string
            URI request_uri = request.getRequestURI();
            String request_method = request.getMethod();
            String nonce = ah_c.getNonce();
            String algrm = ah_c.getAlgorithm();
            String realm = ah_c.getRealm();
            String username = name + "@open-ims.test";
            String password = name;

            MessageDigest mdigest;
            mdigest = MessageDigest.getInstance("MD5");
            DigestServerAuthenticationHelper Str = null;

            // A1
            String A1 = username + ":" + realm + ":" + password;

            String HA1 = DigestServerAuthenticationHelper.toHexString(mdigest.digest(A1.getBytes()));

            // A2
            String A2 = request_method.toUpperCase() + ":" + request_uri;
            String HA2 = DigestServerAuthenticationHelper.toHexString(mdigest.digest(A2.getBytes()));

            // KD
            String KD = HA1 + ":" + nonce + ":" + HA2;
            String responsenew = DigestServerAuthenticationHelper.toHexString(mdigest.digest(KD.getBytes()));

            ah_r.setRealm(realm);
            ah_r.setNonce(nonce);
            ah_r.setUsername(username);
            ah_r.setURI(request_uri);
            ah_r.setAlgorithm(algrm);
            ah_r.setResponse(responsenew);
            return ah_r;
        } catch (Exception e) {
            logger.info("oh hell");
        }
        return nothing;
    }

    @Override

    public void processTimeout(javax.sip.TimeoutEvent timeoutEvent) {

        logger.info("Transaction Time out");
    }

    public void sendCancel() {
        try {
            logger.info("Sending cancel");
            Request cancelRequest = inviteTid.createCancel();
            ClientTransaction cancelTid = sipProvider.getNewClientTransaction(cancelRequest);
            cancelTid.sendRequest();
        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }

    public void init() {
        String n = null;
        name = sipHandler.getname(n);
        SipFactory sipFactory = null;
        sipStack = null;
        sipFactory = SipFactory.getInstance();
        sipFactory.setPathName("gov.nist");
        Properties properties = new Properties();
        String transport = "udp";
        String peerHostPort = "163.17.21.188:5060"; // 5070
        properties.setProperty("javax.sip.OUTBOUND_PROXY", peerHostPort + "/" + transport);
        // If you want to use UDP then uncomment this.
        properties.setProperty("javax.sip.STACK_NAME", "shootist");

        // The following properties are specific to nist-sip
        // and are not necessarily part of any other jain-sip
        // implementation.
        // You can set a max message size for tcp transport to
        // guard against denial of service attack.
        properties.setProperty("gov.nist.javax.sip.DEBUG_LOG", "shootistdebug.txt");
        properties.setProperty("gov.nist.javax.sip.SERVER_LOG", "shootistlog.txt");

        // Drop the client connection after we are done with the transaction.
        properties.setProperty("gov.nist.javax.sip.CACHE_CLIENT_CONNECTIONS", "false");
        // Set to 0 (or NONE) in your production code for max speed.
        // You need 16 (or TRACE) for logging traces. 32 (or DEBUG) for debug + traces.
        // Your code will limp at 32 but it is best for debugging.
        properties.setProperty("gov.nist.javax.sip.TRACE_LEVEL", "32");

        try {
            // Create SipStack object
            sipStack = sipFactory.createSipStack(properties);
            logger.info("createSipStack " + sipStack);
        } catch (PeerUnavailableException e) {
            // could not find
            // gov.nist.jain.protocol.ip.sip.SipStackImpl
            // in the classpath
            e.printStackTrace();
            System.err.println(e.getMessage());
        }

        try {
            headerFactory = sipFactory.createHeaderFactory();
            addressFactory = sipFactory.createAddressFactory();
            messageFactory = sipFactory.createMessageFactory();
            udpListeningPoint = sipStack.createListeningPoint("163.17.21.75", 5060, "udp"); // local IP
            sipProvider = sipStack.createSipProvider(udpListeningPoint);
            shootist listener = this;
            sipProvider.addSipListener(listener);
        } catch (Exception ex) {
        }

        try {
            String fromName = name;
            String fromSipAddress = "open-ims.test";
            // String fromDisplayName = "sis";

            String toSipAddress = "open-ims.test";
            String toUser = name;
            // String toDisplayName = "sis";

            // create >From Header
            SipURI fromAddress = addressFactory.createSipURI(fromName, fromSipAddress);
            Address fromNameAddress = addressFactory.createAddress(fromAddress);
            // fromNameAddress.setDisplayName(fromDisplayName);
            FromHeader fromHeader = headerFactory.createFromHeader(fromNameAddress, "12345");

            // create To Header
            SipURI toAddress = addressFactory.createSipURI(toUser, toSipAddress);
            Address toNameAddress = addressFactory.createAddress(toAddress);
            // toNameAddress.setDisplayName(toDisplayName);
            ToHeader toHeader = headerFactory.createToHeader(toNameAddress, null);

            // create Request URI
            // If response is 403 Forbidden - Domain not serviced edit peerHostPort to domain
            URI requestURI = addressFactory.createURI("sip:" + name + "@open-ims.test"/* peerHostPort */);

            // Create ViaHeader
            ArrayList viaHeaders = new ArrayList();
            ViaHeader viaHeader = headerFactory.createViaHeader("163.17.21.75", 5060, transport, null);

            // add via headers
            viaHeaders.add(viaHeader);

            // Create ContentTypeHeader
            ContentTypeHeader contentTypeHeader = headerFactory.createContentTypeHeader("application", "sdp");

            // Create a new CallId header
            CallIdHeader callIdHeader = sipProvider.getNewCallId();
            callID = callIdHeader;

            // Create a new Cseq header
            CSeqHeader cSeqHeader = headerFactory.createCSeqHeader(invco, Request.REGISTER);

            // Create a new MaxForwardsHeader
            MaxForwardsHeader maxForwards = headerFactory.createMaxForwardsHeader(70);

            // Create the request.
            Request request = messageFactory.createRequest(requestURI, Request.REGISTER, callIdHeader, cSeqHeader,
                    fromHeader, toHeader, viaHeaders, maxForwards);

            // route search
            Address routeaddress = addressFactory.createAddress("sip:orig@scscf.open-ims.test:5060;lr");
            RouteHeader routeHeader = shootist.headerFactory.createRouteHeader(routeaddress);
            // request.addHeader(routeHeader);

            // Create contact headers
            String host = "163.17.21.188";
            Header contactH;
            // contactH = headerFactory.createHeader("Contact",
            // "<sip:sis@open-ims.test:5060;transport=udp>;expires=60;+g.oma.sip-im;language=\"en,fr\";+g.3gpp.smsip;+g.oma.sip-im.large-message");
            // request.addHeader(contactH);
            /*
             * SipURI contactUrl = addressFactory.createSipURI(fromName, host);
             * contactUrl.setPort(udpListeningPoint.getPort());
             * contactUrl.setLrParam();
             */
            // Create the contact name address.
            SipURI contactURI = addressFactory.createSipURI(fromName, host);
            contactURI.setPort(sipProvider.getListeningPoint(transport).getPort());
            Address contactAddress = addressFactory.createAddress(contactURI);

            // Add the contact address.
            // contactAddress.setDisplayName(fromName);
            // contactHeader = headerFactory.createContactHeader(contactAddress);
            // request.addHeader(contactHeader);

            contactH = headerFactory.createHeader("Contact", "<sip:" + name + "@open-ims.test:5060"
                    + ";transport=udp>;expires=60;+g.oma.sip-im;language=\"en,fr\";+g.3gpp.smsip;+g.oma.sip-im.large-message;audio;+g.3gpp.icsi-ref=\"urn%3Aurn-7%3A3gpp-application.ims.iari.gsma-vs\";+g.3gpp.cs-voice"); // my_add
            contactHeader = headerFactory.createContactHeader(contactAddress);
            contactHeader.setExpires(60);
            contactHeader.setParameter("language", "en,fr");
            request.addHeader(contactH);

            /*
             * ++++++++++++++++++++++++++++++++++++++++++++
             * IMS headers
             * ++++++++++++++++++++++++++++++++++++++++++++
             */

            // work-around for IMS header
            HeaderFactoryImpl headerFactoryImpl = new HeaderFactoryImpl();

            AllowHeader allow1 = headerFactory.createAllowHeader(Request.REGISTER);
            request.addHeader(allow1);

            int expires = 60;
            Expires ExpiresHead = (Expires) headerFactory.createExpiresHeader(expires);
            request.addHeader(ExpiresHead);

            // Create the client transaction.
            inviteTid = sipProvider.getNewClientTransaction(request);

            // send the request out.
            inviteTid.sendRequest();

            dialog = inviteTid.getDialog();
            logger.info("--------------------------------Sent registar--------------------------------");
        } catch (Exception ex) {
            logger.info(ex.getMessage());
            ex.printStackTrace();
        }
    }

    @Override
    public void processIOException(IOExceptionEvent exceptionEvent) {
        logger.info("IOException happened for " + exceptionEvent.getHost() + " port = " + exceptionEvent.getPort());

    }

    @Override
    public void processTransactionTerminated(TransactionTerminatedEvent transactionTerminatedEvent) {
        logger.info("Transaction terminated event recieved");
    }

    @Override
    public void processDialogTerminated(DialogTerminatedEvent dialogTerminatedEvent) {
        logger.info("dialogTerminatedEvent");

    }
}
