<%@page import="blackboard.base.*,
    blackboard.persist.*,
    blackboard.platform.*,
    blackboard.data.*,
    blackboard.data.user.*,
    blackboard.data.navigation.*,
    blackboard.data.user.User.*,
    blackboard.persist.navigation.*,
    blackboard.data.registry.*,
    blackboard.persist.registry.*,
    blackboard.portal.data.*,
    blackboard.portal.persist.*,
    blackboard.portal.servlet.*,
    java.security.MessageDigest,
    java.net.*"
    errorPage="/error.jsp" %>

<%@ taglib uri="/bbUI" prefix="bbUI"%>
<%@ taglib uri="/bbData" prefix="bbData"%>

<bbData:context>

<%

    String Uid;
    long timestamp = System.currentTimeMillis() / 1000l;
    Uid = bbContext.getUser().getUserName();

	 // serverURL = your mdid3 server url 
    String serverURL = "https://mdid3.university.edu/";
    // this must match the value of SSO_SECRET in settings_sso.py 
    String mdid3Secret = "zp*+x2)p6q)ft6han8rn8717d#h#2hk$4s-2f*8n*1fw&04h+j";

    String plainText = bbContext.getUser().getUserName() + timestamp + mdid3Secret;

    MessageDigest md = MessageDigest.getInstance("MD5");
    md.update(plainText.getBytes());


    byte[] digest = md.digest();
    StringBuffer hexString = new StringBuffer();

    for (int i = 0; i < digest.length; i++) {

        plainText = Integer.toHexString(0xFF & digest[i]);

        if (plainText.length() < 2) {
            plainText = "0" + plainText;
        }

        hexString.append(plainText);

    }

    String theHash;
    theHash = hexString.toString();
    theHash = theHash.toUpperCase();
    response.sendRedirect (serverURL + "?id=" + Uid + "&timestamp=" + timestamp + "&token=" + theHash + "");

%>

</bbData:context>

