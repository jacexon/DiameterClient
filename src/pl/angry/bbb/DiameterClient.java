package pl.angry.bbb;

import dk.i1.diameter.*;
import dk.i1.diameter.node.*;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.NoSuchAlgorithmException;

/**
 * Created by Kamil on 2016-12-26.
 */
public class DiameterClient {

    String host_id;
    String realm;
    String dest_host;
    int dest_port;
    String password;
    String secret;
    String username;
    String clusterAddress;

    SimpleSyncClient ssc;

    public DiameterClient(String host_id, String realm, String dest_host, int dest_port) {
        this.host_id = host_id;
        this.realm = realm;
        this.dest_host = dest_host;
        this.dest_port = dest_port;
    }

    public String getClusterAddress() {
        return clusterAddress;
    }

    public void setClusterAddress(String clusterAddress) {
        this.clusterAddress = clusterAddress;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getHost_id() {
        return host_id;
    }

    public void setHost_id(String host_id) {
        this.host_id = host_id;
    }

    public String getRealm() {
        return realm;
    }

    public void setRealm(String realm) {
        this.realm = realm;
    }

    public String getDest_host() {
        return dest_host;
    }

    public void setDest_host(String dest_host) {
        this.dest_host = dest_host;
    }

    public int getDest_port() {
        return dest_port;
    }

    public void setDest_port(int dest_port) {
        this.dest_port = dest_port;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getSecret() {
        return secret;
    }

    public void setSecret(String secret) {
        this.secret = secret;
    }


    void start() throws EmptyHostNameException, IOException, UnsupportedTransportProtocolException, InterruptedException {

        Capability capability = new Capability();
        capability.addAuthApp(ProtocolConstants.DIAMETER_APPLICATION_CREDIT_CONTROL
        );
        NodeSettings node_settings;
        try {
            node_settings  = new NodeSettings(
                    host_id, realm,
                    99999, //vendor-id
                    capability,
                    0,
                    "Client", 0x01000000);
        } catch (InvalidSettingException e) {
            System.out.println(e.toString());
            return;
        }

        Peer peers[] = new Peer[]{
                new Peer(dest_host,dest_port)
        };

        ssc = new SimpleSyncClient(node_settings,peers);
        ssc.start();
        ssc.waitForConnection(); //allow connection to be established.

    }

    void runAaProcess() {

        //Build Credit-Control Request
        // <Credit-Control-Request> ::= < Diameter Header: 272, REQ, PXY >
        Message authWithPassRequest = buildBasicMessage();

        Utils.setMandatory_RFC3588(authWithPassRequest);
        Utils.setMandatory_RFC4006(authWithPassRequest);

        //Send password
        Message authWithPassReply = ssc.sendRequest(authWithPassRequest);

        Message nextMessageToSend = processReply(authWithPassReply);
        if (nextMessageToSend != null) {
            //send chap response

            /*try { //to jest do pokazania, ze jak timeout minie to kapota
                Thread.sleep(10000);
            } catch (InterruptedException e) {
                e.printStackTrace();
            }*/

            Message finalReply = ssc.sendRequest(nextMessageToSend);

            //pokaz z powtorzonym pakietem
            //ssc.sendRequest(nextMessageToSend);

            processReply(finalReply);
        }


    }

    Message processReply(Message reply)
    {
        Message nextMessage = null;
        //Now look at the result
        if(reply==null) {
            System.out.println("Brak odpowiedzi");
            return null;
        }

        AVP result_code = reply.find(ProtocolConstants.DI_RESULT_CODE);
        if(result_code==null) {
            System.out.println("Brak kodu wyniku");
            return null;
        }
        try {
            AVP_Unsigned32 result_code_u32 = new AVP_Unsigned32(result_code);
            int rc = result_code_u32.queryValue();
            AVP avp;
            switch(rc) {
                case ProtocolConstants.DIAMETER_RESULT_MULTI_ROUND_AUTH:
                    System.out.println("Wielorundowe uwierzytelnienie");
                    avp = reply.find(ProtocolConstants.DI_CHAP_AUTH);
                    try {

                        AVP_Grouped chapAuth = new AVP_Grouped( avp);
                        AVP[] elements = chapAuth.queryAVPs();
                        if (new AVP_Integer32(elements[0]).queryValue() != 5){
                            System.out.println("Nieznany sposób wielorundowego uwierzytelnienia ");
                            return null;
                        }
                        //byte[] bytes = new AVP_OctetString(elements[1]).queryValue() ;
                        byte[] idBytes = new AVP_OctetString(elements[1]).queryValue();
                        char id = (char) idBytes[0];
                        System.out.println("id: " + id );
                        byte[] chapChallengeBytes = new AVP_OctetString(elements[2]).queryValue();
                        String chapChallenge = chapChallengeBytes.toString();
                        //System.out.println("chapChallenge: " + chapChallenge );
                        printBytesAsString(chapChallengeBytes, "odebrane zadanie ");
                        byte[] rozwiazanie = caluculateMD5( idBytes, secret.getBytes("ASCII"), chapChallengeBytes);
                        printBytesAsString(rozwiazanie, "obliczone rozwiazanie ");
                        chapAuth.setAVPs(elements[0], elements[1],
                                new AVP_OctetString(ProtocolConstants.DI_CHAP_RESPONSE,rozwiazanie),
                                elements[2]);

                        nextMessage = buildBasicMessage();
                        nextMessage.add(chapAuth);
                        Utils.setMandatory_RFC3588(nextMessage);
                        Utils.setMandatory_RFC4006(nextMessage);
                    } catch (InvalidAVPLengthException e) {
                        e.printStackTrace();
                    } catch (UnsupportedEncodingException e) {
                        e.printStackTrace();
                    }
                    break;

                case ProtocolConstants.DIAMETER_RESULT_SUCCESS: {
                    System.out.println("Sukces");
                    avp =  reply.find(ProtocolConstants.DI_FRAMED_IP_ADDRESS);
                    if (avp != null) {
                        AVP_OctetString multicastAdress = new AVP_OctetString(avp );
                        if (multicastAdress != null) {
                            clusterAddress = new String(multicastAdress.queryValue());
                            System.out.println("adres IP klastra: " + clusterAddress);
                        }
                    }


                    // tutaj wywolujemy metode rozpoczynajaca komunikacje z hostami w klastrze
                    break;
                }
                case ProtocolConstants.DIAMETER_RESULT_END_USER_SERVICE_DENIED:
                    System.out.println("End user service denied");
                    break;
                case ProtocolConstants.DIAMETER_RESULT_CREDIT_CONTROL_NOT_APPLICABLE:
                    System.out.println("Credit-control not applicable");
                    break;
                case ProtocolConstants.DIAMETER_RESULT_CREDIT_LIMIT_REACHED:
                    System.out.println("Credit-limit reached");
                    break;
                case ProtocolConstants.DIAMETER_RESULT_USER_UNKNOWN:
                    System.out.println("User unknown");
                    break;
                case ProtocolConstants.DIAMETER_RESULT_RATING_FAILED:
                    System.out.println("Rating failed");
                    break;
                case ProtocolConstants.DIAMETER_RESULT_AUTHENTICATION_REJECTED:
                    System.out.println("Access denied");
                    break;
                default:
                    //Some other error
                    //There are too many to decode them all.
                    //We just print the classification
                    if(rc>=1000 && rc<1999)
                        System.out.println("Informational: " + rc);
                    else if(rc>=2000 && rc<2999)
                        System.out.println("Success: " + rc);
                    else if(rc>=3000 && rc<3999)
                        System.out.println("Protocl error: " + rc);
                    else if(rc>=4000 && rc<4999)
                        System.out.println("Transient failure: " + rc);
                    else if(rc>=5000 && rc<5999)
                        System.out.println("Permanent failure: " + rc);
                    else
                        System.out.println("(unknown error class): " + rc);

            }

        } catch(InvalidAVPLengthException ex) {
            System.out.println("result-code was illformed");
            return null;
        }
        return nextMessage;
    }

    Message buildBasicMessage() {
        Message message = new Message();
        message.hdr.command_code = ProtocolConstants.DIAMETER_COMMAND_AA;
        message.hdr.application_id = ProtocolConstants.DIAMETER_APPLICATION_CREDIT_CONTROL;
        message.hdr.setRequest(true);
        message.hdr.setProxiable(true);

        message.add(new AVP_UTF8String(ProtocolConstants.DI_SESSION_ID,ssc.node().makeNewSessionId()));//

        ssc.node().addOurHostAndRealm(message);

        message.add(new AVP_UTF8String(ProtocolConstants.DI_DESTINATION_REALM, realm));//

        message.add(new AVP_Unsigned32(ProtocolConstants.DI_AUTH_APPLICATION_ID,ProtocolConstants.DIAMETER_APPLICATION_CREDIT_CONTROL)); // a lie but a minor one//

        message.add(new AVP_Unsigned32(ProtocolConstants.DI_AUTH_REQUEST_TYPE,ProtocolConstants.DI_AUTH_REQUEST_TYPE_AUTHENTICATE));;

        message.add(new AVP_UTF8String(ProtocolConstants.DI_USER_NAME, username + "@" + realm));

        message.add(new AVP_UTF8String(ProtocolConstants.DI_USER_PASSWORD, password));

        message.add(new AVP_Unsigned32(ProtocolConstants.DI_ORIGIN_STATE_ID,ssc.node().stateId()));
        return message;

    }
    void stop() {
        //Stop the stack
        ssc.stop();
    }

    public byte[] caluculateMD5(byte[] id, byte[] secret, byte[] chellange) {
        java.security.MessageDigest md = null;
        byte[] word = concatenateBytes(
                concatenateBytes(id,secret), chellange);
        printBytesAsString(word, "licze md5 dla ");
        try {
            md = java.security.MessageDigest.getInstance("MD5");
            md.reset();
            md.update(word);
            return md.digest();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return null;
    }

    void printBytesAsString(byte[] bytes, String text)  {
        char[] charChallange2 = new char[bytes.length];
        for( int i = 0; i < bytes.length; i++) {
            charChallange2[i] = (char) bytes[i];

        }
        System.out.println(text + String.valueOf(charChallange2));
    }

    byte[] concatenateBytes(byte[] a, byte[] b) {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream( );
        try {
            outputStream.write( a );
            outputStream.write( b );
        } catch (IOException e) {
            e.printStackTrace();
        }
        return outputStream.toByteArray( );
    }
}
