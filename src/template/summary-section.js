//---------------------------------------------------------- vars ---------------------------------------------------------------
var cxIconPath = "/cxReport/src/img/CxIcon48x48.png";

var SEVERITY = {
    HIGH: {value: 0, name: "high"},
    MED: {value: 1, name: "medium"},
    LOW: {value: 2, name: "low"},
    OSA_HIGH: {value: 3, name: "high"},
    OSA_MED: {value: 4, name: "medium"},
    OSA_LOW: {value: 5, name: "low"}
};

var thresholdExceededHtml =
    '<div class="threshold-exceeded">' +
    '<div class="threshold-exceeded-icon">' +
    '<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" xmlns:svgjs="http://svgjs.com/svgjs" id="SvgjsSvg1015" version="1.1" width="9.400000000000091" height="12.399999999999977" viewBox="0 0 9.400000000000091 12.399999999999977"><title>threshold ICON</title><desc>Created with Avocode.</desc><defs id="SvgjsDefs1016"/><path id="SvgjsPath1017" d="M1052 190L1056.29 190L1056.29 195.6L1052 195.6Z " fill="#da2945" fill-opacity="1" transform="matrix(1,0,0,1,-1049.3,-184.3)"/><path id="SvgjsPath1018" d="M1052.71 185.1L1055.57 185.1 " fill-opacity="0" fill="#ffffff" stroke-dasharray="0" stroke-linejoin="miter" stroke-linecap="square" stroke-opacity="1" stroke="#da2945" stroke-miterlimit="50" stroke-width="1.4" transform="matrix(1,0,0,1,-1049.3,-184.3)"/><path id="SvgjsPath1019" d="M1052.71 188.1L1055.57 188.1 " fill-opacity="0" fill="#ffffff" stroke-dasharray="0" stroke-linejoin="miter" stroke-linecap="square" stroke-opacity="1" stroke="#da2945" stroke-miterlimit="50" stroke-width="1.4" transform="matrix(1,0,0,1,-1049.3,-184.3)"/><path id="SvgjsPath1020" d="M1050.42 195.1L1057.64 195.1 " fill-opacity="0" fill="#ffffff" stroke-dasharray="0" stroke-linejoin="miter" stroke-linecap="square" stroke-opacity="1" stroke="#da2945" stroke-miterlimit="50" stroke-width="1.4" transform="matrix(1,0,0,1,-1049.3,-184.3)"/></svg>' +
    '</div>' +
    '<div class="threshold-exceeded-text">' +
    'Threshold Exceeded' +
    '</div>' +
    '</div>';

var thresholdComplianceHtml =
    '<div class="threshold-compliance">' +
    '<div class="threshold-compliance-icon">' +
    '<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" xmlns:svgjs="http://svgjs.com/svgjs" id="SvgjsSvg1050" version="1.1" width="13.99264158479491" height="13" viewBox="0 0 13.99264158479491 13"><title>Icon</title><desc>Created with Avocode.</desc><defs id="SvgjsDefs1051"><clipPath id="SvgjsClipPath1056"><path id="SvgjsPath1055" d="M1035.00736 793.9841L1035.00736 784.01589L1046.9926400000002 784.01589L1046.9926400000002 793.9841ZM1038.67 790.72L1036.68 788.72L1036 789.4L1038.67 792.0699999999999L1045.21 785.67L1044.54 785Z " fill="#ffffff"/></clipPath></defs><path id="SvgjsPath1052" d="M1033 789.5C1033 785.91015 1035.91015 783 1039.5 783C1043.08985 783 1046 785.91015 1046 789.5C1046 793.08985 1043.08985 796 1039.5 796C1035.91015 796 1033 793.08985 1033 789.5Z " fill="#21bf3f" fill-opacity="1" transform="matrix(1,0,0,1,-1033,-783)"/><path id="SvgjsPath1053" d="M1038.67 790.72L1036.68 788.72L1036 789.4L1038.67 792.0699999999999L1045.21 785.67L1044.54 785Z " fill="#ffffff" fill-opacity="1" transform="matrix(1,0,0,1,-1033,-783)"/><path id="SvgjsPath1054" d="M1038.67 790.72L1036.68 788.72L1036 789.4L1038.67 792.0699999999999L1045.21 785.67L1044.54 785Z " fill-opacity="0" fill="#ffffff" stroke-dasharray="0" stroke-linejoin="miter" stroke-linecap="butt" stroke-opacity="1" stroke="#ffffff" stroke-miterlimit="50" stroke-width="1.4" clip-path="url(&quot;#SvgjsClipPath1056&quot;)" transform="matrix(1,0,0,1,-1033,-783)"/></svg>' +
    '</div>' +
    '<div class="threshold-compliance-text">' +
    'Threshold Compliance' +
    '</div>' +
    '</div>';


//-------------------------- sast vars --------------------------------------
var pdfReportReady = true;

//thresholds - Legacy form
var thresholdsEnabled = false;
var highThreshold = 199;
var medThreshold = 10;
var lowThreshold = 3;

//counts - Legacy form
var highCount = 200;
var medCount = 100;
var lowCount = 1;

//cve lists
var highCveList = [{"prettyName": "SQL Injection", "name": "SQL_Injection", "severity": "3", "count": 1}];
var medCveList = [{"prettyName": "Parameter Tampering", "name": "Parameter_Tampering", "severity": "2", "count": 1}];
var lowCveList = [{
    "prettyName": "Improper Exception Handling",
    "name": "Improper_Exception_Handling",
    "severity": "1",
    "count": 3
}, {"prettyName": "Improper Resource Access Authorization", "name": "Improper_Resource_Access_Authorization", "severity": "1", "count": 1}];

//-------------------------- osa vars --------------------------------------
//Legacy form
var osaEnabled = true;

//libraries - Legacy form
var osaVulnerableAndOutdatedLibs = 456;
var okLibraries = 0;

//thresholds - Legacy form
var osaThresholdsEnabled = true;
var osaHighThreshold = 1;
var osaMedThreshold = 3;
var osaLowThreshold = 5;

//counts - Legacy form
var osaHighCount = 2;
var osaMedCount = 9;
var osaLowCount = 10;

//cve lists - New (8.4.2 and up)
var osaHighCveList = [{
    "id": "98DDAFAF9DED4A98AC13A788477D557057125E0E",
    "cveName": "CVE-2015-4852",
    "score": 7.5,
    "severity": {
        "id": 2,
        "name": "High"
    },
    "publishDate": "18-11-2015",
    "url": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-4852",
    "description": "The WLS Security component in Oracle WebLogic Server 10.3.6.0, 12.1.2.0, 12.1.3.0, and 12.2.1.0 allows remote attackers to execute arbitrary commands via a crafted serialized Java object in T3 protocol traffic to TCP port 7001, related to oracle_common/modules/com.bea.core.apache.commons.collections.jar. NOTE: the scope of this CVE is limited to the WebLogic Server product.",
    "recommendations": null,
    "sourceFileName": null,
    "libraryId": "B346B1CA8CCDC8DC9336D2B5D34E960C256853F3",
    "libraryName": "commons-collections-2.1.jar"
}, {
    "id": "65BD9AD939FECC46A50FE34E4255CDD26983E376",
    "cveName": "CVE-2015-6420",
    "score": 7.5,
    "severity": {
        "id": 2,
        "name": "High"
    },
    "publishDate": "15-12-2015",
    "url": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-6420",
    "description": "Serialized-object interfaces in certain Cisco Collaboration and Social Media; Endpoint Clients and Client Software; Network Application, Service, and Acceleration; Network and Content Security Devices; Network Management and Provisioning; Routing and Switching - Enterprise and Service Provider; Unified Computing; Voice and Unified Communications Devices; Video, Streaming, TelePresence, and Transcoding Devices; Wireless; and Cisco Hosted Services products allow remote attackers to execute arbitrary commands via a crafted serialized Java object, related to the Apache Commons Collections (ACC) library.",
    "recommendations": null,
    "sourceFileName": null,
    "libraryId": "B346B1CA8CCDC8DC9336D2B5D34E960C256853F3",
    "libraryName": "commons-collections-2.1.jar"
}, {
    "id": "BF8210DC9D1188413951C56A9A1AB8A0F69AA982",
    "cveName": "CVE-2015-7501",
    "score": 7.3,
    "severity": {
        "id": 2,
        "name": "High"
    },
    "publishDate": "09-11-2015",
    "url": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-7501",
    "description": "It was found that the Apache commons-collections library permitted code execution when deserializing objects involving a specially constructed chain of classes. A remote attacker could use this flaw to execute arbitrary code with the permissions of the application using the commons-collections library.",
    "recommendations": "Upgrade to version apache-commons-collections 4.1, apache-commons-collections 3.2.2 or greater",
    "sourceFileName": null,
    "libraryId": "B346B1CA8CCDC8DC9336D2B5D34E960C256853F3",
    "libraryName": "commons-collections-2.1.jar"
}, {
    "id": "8286F1306CB21C7E71E0B5AD77A1AE7335CC185C",
    "cveName": "CVE-2014-0114",
    "score": 7.5,
    "severity": {
        "id": 2,
        "name": "High"
    },
    "publishDate": "30-04-2014",
    "url": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-0114",
    "description": "Apache Commons BeanUtils, as distributed in lib/commons-beanutils-1.8.0.jar in Apache Struts 1.x through 1.3.10 and in other products requiring commons-beanutils through 1.9.2, does not suppress the class property, which allows remote attackers to \"manipulate\" the ClassLoader and execute arbitrary code via the class parameter, as demonstrated by the passing of this parameter to the getClass method of the ActionForm object in Struts 1.",
    "recommendations": "All Commons BeanUtils users should upgrade to the latest version >= commons-beanutils-1.9.2\n",
    "sourceFileName": null,
    "libraryId": "CD0C64BA7869B39D2204ECF37AE200D0240FAD94",
    "libraryName": "commons-beanutils-1.8.3.jar"
}];
var osaMedCveList = [{
    "id": "B8F450A0D0077E0481D3273896F34F6E38BFFCD0",
    "cveName": "CVE-2012-4529",
    "score": 4.3,
    "severity": {
        "id": 1,
        "name": "Medium"
    },
    "publishDate": "28-10-2013",
    "url": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2012-4529",
    "description": "The org.apache.catalina.connector.Response.encodeURL method in Red Hat JBoss Web 7.1.x and earlier, when the tracking mode is set to COOKIE, sends the jsessionid in the URL of the first response of a session, which allows remote attackers to obtain the session id (1) via a man-in-the-middle attack or (2) by reading a log.",
    "recommendations": null,
    "sourceFileName": null,
    "libraryId": "56DAEE4E3186AEA248E88A59CDB6615B157424D8",
    "libraryName": "tomcat-catalina-7.0.47.jar"
}, {
    "id": "B33765B1BBE4E1E256162963C668C8B24E878D3A",
    "cveName": "CVE-2013-4590",
    "score": 4.3,
    "severity": {
        "id": 1,
        "name": "Medium"
    },
    "publishDate": "26-02-2014",
    "url": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2013-4590",
    "description": "Apache Tomcat before 6.0.39, 7.x before 7.0.50, and 8.x before 8.0.0-RC10 allows attackers to obtain \"Tomcat internals\" information by leveraging the presence of an untrusted web application with a context.xml, web.xml, *.jspx, *.tagx, or *.tld XML document containing an external entity declaration in conjunction with an entity reference, related to an XML External Entity (XXE) issue.",
    "recommendations": "All Tomcat 6.0.x users should upgrade to the latest version >= tomcat-6.0.41\nAll Tomcat 7.0.x users should upgrade to the latest version >= tomcat-7.0.56\n",
    "sourceFileName": null,
    "libraryId": "56DAEE4E3186AEA248E88A59CDB6615B157424D8",
    "libraryName": "tomcat-catalina-7.0.47.jar"
}, {
    "id": "5AED226E0483837167DFAAADF8155354E41CC8C6",
    "cveName": "CVE-2014-0096",
    "score": 4.3,
    "severity": {
        "id": 1,
        "name": "Medium"
    },
    "publishDate": "31-05-2014",
    "url": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-0096",
    "description": "java/org/apache/catalina/servlets/DefaultServlet.java in the default servlet in Apache Tomcat before 6.0.40, 7.x before 7.0.53, and 8.x before 8.0.4 does not properly restrict XSLT stylesheets, which allows remote attackers to bypass security-manager restrictions and read arbitrary files via a crafted web application that provides an XML external entity declaration in conjunction with an entity reference, related to an XML External Entity (XXE) issue.",
    "recommendations": "All Tomcat 6.0.x users should upgrade to the latest version >= tomcat-6.0.41\nAll Tomcat 7.0.x users should upgrade to the latest version >= tomcat-7.0.56\n",
    "sourceFileName": null,
    "libraryId": "56DAEE4E3186AEA248E88A59CDB6615B157424D8",
    "libraryName": "tomcat-catalina-7.0.47.jar"
}, {
    "id": "CC538F3F9090BB857CC7435F45855BBCB3F573E5",
    "cveName": "CVE-2014-0119",
    "score": 4.3,
    "severity": {
        "id": 1,
        "name": "Medium"
    },
    "publishDate": "31-05-2014",
    "url": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-0119",
    "description": "Apache Tomcat before 6.0.40, 7.x before 7.0.54, and 8.x before 8.0.6 does not properly constrain the class loader that accesses the XML parser used with an XSLT stylesheet, which allows remote attackers to (1) read arbitrary files via a crafted web application that provides an XML external entity declaration in conjunction with an entity reference, related to an XML External Entity (XXE) issue, or (2) read files associated with different web applications on a single Tomcat instance via a crafted web application.",
    "recommendations": "All Tomcat 6.0.x users should upgrade to the latest version >= tomcat-6.0.41\nAll Tomcat 7.0.x users should upgrade to the latest version >= tomcat-7.0.56\n",
    "sourceFileName": null,
    "libraryId": "56DAEE4E3186AEA248E88A59CDB6615B157424D8",
    "libraryName": "tomcat-catalina-7.0.47.jar"
}, {
    "id": "A3868B78EE949AA133B6F4E4705D0D999D1C0DFF",
    "cveName": "CVE-2015-5345",
    "score": 5.0,
    "severity": {
        "id": 1,
        "name": "Medium"
    },
    "publishDate": "24-02-2016",
    "url": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-5345",
    "description": "The Mapper component in Apache Tomcat 6.x before 6.0.45, 7.x before 7.0.67, 8.x before 8.0.30, and 9.x before 9.0.0.M2 processes redirects before considering security constraints and Filters, which allows remote attackers to determine the existence of a directory via a URL that lacks a trailing / (slash) character.",
    "recommendations": null,
    "sourceFileName": null,
    "libraryId": "56DAEE4E3186AEA248E88A59CDB6615B157424D8",
    "libraryName": "tomcat-catalina-7.0.47.jar"
}, {
    "id": "C32CA80DA2A3306F8EDF5BBBF09F23F7B96CB9C6",
    "cveName": "CVE-2015-5346",
    "score": 6.8,
    "severity": {
        "id": 1,
        "name": "Medium"
    },
    "publishDate": "24-02-2016",
    "url": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-5346",
    "description": "Session fixation vulnerability in Apache Tomcat 7.x before 7.0.66, 8.x before 8.0.30, and 9.x before 9.0.0.M2, when different session settings are used for deployments of multiple versions of the same web application, might allow remote attackers to hijack web sessions by leveraging use of a requestedSessionSSL field for an unintended request, related to CoyoteAdapter.java and Request.java.",
    "recommendations": null,
    "sourceFileName": null,
    "libraryId": "56DAEE4E3186AEA248E88A59CDB6615B157424D8",
    "libraryName": "tomcat-catalina-7.0.47.jar"
}, {
    "id": "0CB2A6BEB3146D6FB18121F4C68101D29DC56BA0",
    "cveName": "CVE-2015-5351",
    "score": 6.8,
    "severity": {
        "id": 1,
        "name": "Medium"
    },
    "publishDate": "24-02-2016",
    "url": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-5351",
    "description": "The (1) Manager and (2) Host Manager applications in Apache Tomcat 7.x before 7.0.68, 8.x before 8.0.31, and 9.x before 9.0.0.M2 establish sessions and send CSRF tokens for arbitrary new requests, which allows remote attackers to bypass a CSRF protection mechanism by using a token.",
    "recommendations": null,
    "sourceFileName": null,
    "libraryId": "56DAEE4E3186AEA248E88A59CDB6615B157424D8",
    "libraryName": "tomcat-catalina-7.0.47.jar"
}, {
    "id": "4F078C4F6AFE11FE22717CB9508282F60C412B9B",
    "cveName": "CVE-2016-0706",
    "score": 4.0,
    "severity": {
        "id": 1,
        "name": "Medium"
    },
    "publishDate": "24-02-2016",
    "url": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-0706",
    "description": "Apache Tomcat 6.x before 6.0.45, 7.x before 7.0.68, 8.x before 8.0.31, and 9.x before 9.0.0.M2 does not place org.apache.catalina.manager.StatusManagerServlet on the org/apache/catalina/core/RestrictedServlets.properties list, which allows remote authenticated users to bypass intended SecurityManager restrictions and read arbitrary HTTP requests, and consequently discover session ID values, via a crafted web application.",
    "recommendations": null,
    "sourceFileName": null,
    "libraryId": "56DAEE4E3186AEA248E88A59CDB6615B157424D8",
    "libraryName": "tomcat-catalina-7.0.47.jar"
}, {
    "id": "A34F2E92DC0206A8E730961CF1AFD3C3EE5CBAC8",
    "cveName": "CVE-2016-0714",
    "score": 6.5,
    "severity": {
        "id": 1,
        "name": "Medium"
    },
    "publishDate": "24-02-2016",
    "url": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-0714",
    "description": "The session-persistence implementation in Apache Tomcat 6.x before 6.0.45, 7.x before 7.0.68, 8.x before 8.0.31, and 9.x before 9.0.0.M2 mishandles session attributes, which allows remote authenticated users to bypass intended SecurityManager restrictions and execute arbitrary code in a privileged context via a web application that places a crafted object in a session.",
    "recommendations": null,
    "sourceFileName": null,
    "libraryId": "56DAEE4E3186AEA248E88A59CDB6615B157424D8",
    "libraryName": "tomcat-catalina-7.0.47.jar"
}, {
    "id": "8057BEBF533E1502AE86384BDC26CEDAD1B89F4A",
    "cveName": "CVE-2016-0763",
    "score": 6.5,
    "severity": {
        "id": 1,
        "name": "Medium"
    },
    "publishDate": "24-02-2016",
    "url": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-0763",
    "description": "The setGlobalContext method in org/apache/naming/factory/ResourceLinkFactory.java in Apache Tomcat 7.x before 7.0.68, 8.x before 8.0.31, and 9.x before 9.0.0.M3 does not consider whether ResourceLinkFactory.setGlobalContext callers are authorized, which allows remote authenticated users to bypass intended SecurityManager restrictions and read or write to arbitrary application data, or cause a denial of service (application disruption), via a web application that sets a crafted global context.",
    "recommendations": null,
    "sourceFileName": null,
    "libraryId": "56DAEE4E3186AEA248E88A59CDB6615B157424D8",
    "libraryName": "tomcat-catalina-7.0.47.jar"
}];
var osaLowCveList = [{
    "id": "E99D85B04F1D2639C7F9F0314D3E684C14FA3FBE",
    "cveName": "CVE-2012-2672",
    "score": 2.1,
    "severity": {
        "id": 0,
        "name": "Low"
    },
    "publishDate": "16-06-2012",
    "url": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2012-2672",
    "description": "Oracle Mojarra 2.1.7 does not properly \"clean up\" the FacesContext reference during startup, which allows local users to obtain context information an access resources from another WAR file by calling the FacesContext.getCurrentInstance function.",
    "recommendations": "Apply the appropriate patch for your system. See References.",
    "sourceFileName": null,
    "libraryId": "7EE88C9A2CF1225A2B779FC86F25E4959A965AB1",
    "libraryName": "jsf-api-2.1.7.jar"
}];

//-------------------------- full reports vars --------------------------------------
var sastPdfPath = 'path/pdf';
var sastHtmlPath = 'path/pdf';
//    http://localhost/CxWebClient/ViewerMain.aspx?scanid=1030692&projectid=40565
var sastCodeViewerPath = 'path/pdf';

var osaHtmlPath = 'path/pdf';
var osaPdfPath = 'path/pdf';

var sastStartDate = 28 / 06 / 2016;
var sastEndtDate = 28 / 06 / 2016;
var sastNumFiles = 1023;
var sastLoc = 5632;

var osaStartDate = 28 / 06 / 2016;
var osaEndtDate = 28 / 06 / 2016;
var osaNumFiles = 28 / 06 / 2016;




document.getElementById("cx-icon-main").setAttribute("src", cxIconPath);
//---------------------------------------------------------- sast ---------------------------------------------------------------
//todo - catch exceptions?
//set bars height and count
document.getElementById("bar-count-high").innerHTML = highCount;
document.getElementById("bar-count-med").innerHTML = medCount;
document.getElementById("bar-count-low").innerHTML = lowCount;

document.getElementById("bar-high").setAttribute("style", "height:" + highCount * 100 / (highCount + medCount + lowCount) + "%");
document.getElementById("bar-med").setAttribute("style", "height:" + medCount * 100 / (highCount + medCount + lowCount) + "%");
document.getElementById("bar-low").setAttribute("style", "height:" + lowCount * 100 / (highCount + medCount + lowCount) + "%");

//if threshold is enabled
if (thresholdsEnabled) {
    var isThresholdExceeded = false;
    var thresholdExceededComplianceElement = document.getElementById("threshold-exceeded-compliance");


    if (highThreshold != null && highCount > highThreshold) {
        document.getElementById("tooltip-high").innerHTML = tooltipGenerator(SEVERITY.HIGH);
        isThresholdExceeded = true;
    }

    if (medThreshold != null && medCount > medThreshold) {
        document.getElementById("tooltip-med").innerHTML = tooltipGenerator(SEVERITY.MED);
        isThresholdExceeded = true;
    }

    if (lowThreshold != null && lowCount > lowThreshold) {
        document.getElementById("tooltip-low").innerHTML = tooltipGenerator(SEVERITY.LOW);
        isThresholdExceeded = true;
    }


    //if threshold exceeded
    if (isThresholdExceeded) {
        thresholdExceededComplianceElement.innerHTML = thresholdExceededHtml;
    }

    //else
    //show threshold compliance element
    else {
        thresholdExceededComplianceElement.innerHTML = thresholdComplianceHtml;
    }
}

//---------------------------------------------------------- osa ---------------------------------------------------------------
if (osaEnabled) {
    //todo - catch exceptions?
    //set bars height and count
    document.getElementById("osa-bar-count-high").innerHTML = numberWithCommas(osaHighCount);
    document.getElementById("osa-bar-count-med").innerHTML = numberWithCommas(osaMedCount);
    document.getElementById("osa-bar-count-low").innerHTML = numberWithCommas(osaLowCount);

    document.getElementById("osa-bar-high").setAttribute("style", "height:" + osaHighCount * 100 / (osaHighCount + osaMedCount + osaLowCount) + "%");
    document.getElementById("osa-bar-med").setAttribute("style", "height:" + osaMedCount * 100 / (osaHighCount + osaMedCount + osaLowCount) + "%");
    document.getElementById("osa-bar-low").setAttribute("style", "height:" + osaLowCount * 100 / (osaHighCount + osaMedCount + osaLowCount) + "%");

    document.getElementById("vulnerable-libraries").innerHTML = numberWithCommas(osaVulnerableAndOutdatedLibs);
    document.getElementById("ok-libraries").innerHTML = numberWithCommas(okLibraries);

    //if threshold is enabled
    if (osaThresholdsEnabled) {
        var isOsaThresholdExceeded = false;
        var osaThresholdExceededComplianceElement = document.getElementById("osa-threshold-exceeded-compliance");


        if (osaHighThreshold != null && osaHighCount > osaHighThreshold) {
            document.getElementById("osa-tooltip-high").innerHTML = tooltipGenerator(SEVERITY.OSA_HIGH);
            isOsaThresholdExceeded = true;
        }

        if (osaMedThreshold != null && osaMedCount > osaMedThreshold) {
            document.getElementById("osa-tooltip-med").innerHTML = tooltipGenerator(SEVERITY.OSA_MED);
            isOsaThresholdExceeded = true;
        }

        if (osaLowThreshold != null && osaLowCount > osaLowThreshold) {
            document.getElementById("osa-tooltip-low").innerHTML = tooltipGenerator(SEVERITY.OSA_LOW);
            isOsaThresholdExceeded = true;
        }


        //if threshold exceeded
        if (isOsaThresholdExceeded) {
            osaThresholdExceededComplianceElement.innerHTML = thresholdExceededHtml;
        }

        //else
        //show threshold compliance element
        else {
            osaThresholdExceededComplianceElement.innerHTML = thresholdComplianceHtml;
        }

    }
}
else {
    document.getElementById("osa-info").setAttribute("style", "display:none");
}

//---------------------------------------------------------- full reports ---------------------------------------------------------------
//sast links
document.getElementById("sast-html-link").setAttribute("href", sastHtmlPath);

//sastPdfPath only if pdfReportReady
if (pdfReportReady) {
    document.getElementById("sast-pdf-link").innerHTML =

        '<a class="pdf-report" href="' + sastPdfPath + '">' +
        '<div class="download-icon">' +
        '<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" xmlns:svgjs="http://svgjs.com/svgjs" id="SvgjsSvg1022" version="1.1" width="13" height="16" viewBox="0 0 13 16"><title>PDF icon</title><desc>Created with Avocode.</desc><defs id="SvgjsDefs1023"><clipPath id="SvgjsClipPath1027"><path id="SvgjsPath1026" d="M271 763L280.1 763L284 767L284 779L271 779Z " fill="#ffffff"/></clipPath></defs><path id="SvgjsPath1024" d="M279 768L279 763L280.1 763L284 767L284 768Z " fill="#373050" fill-opacity="1" transform="matrix(1,0,0,1,-271,-763)"/><path id="SvgjsPath1025" d="M271 763L280.1 763L284 767L284 779L271 779Z " fill-opacity="0" fill="#ffffff" stroke-dasharray="0" stroke-linejoin="miter" stroke-linecap="butt" stroke-opacity="1" stroke="#373050" stroke-miterlimit="50" stroke-width="2" clip-path="url(&quot;#SvgjsClipPath1027&quot;)" transform="matrix(1,0,0,1,-271,-763)"/></svg>' +
        '</div>' +
        '<div class="download-txt">' +
        'PDF Report' +
        '</div>' +
        '</a>';
}

document.getElementById("sast-code-viewer-link").setAttribute("href", sastCodeViewerPath);

//osa links
document.getElementById("osa-html-link").setAttribute("href", osaHtmlPath);
document.getElementById("osa-pdf-link").setAttribute("href", osaPdfPath);

//sast info
document.getElementById("sast-full-start-date").innerHTML = sastStartDate;
document.getElementById("sast-full-end-date").innerHTML = sastEndtDate;
document.getElementById("sast-full-files").innerHTML = numberWithCommas(sastNumFiles);
document.getElementById("sast-full-loc").innerHTML = numberWithCommas(sastLoc);

//osa info
document.getElementById("osa-full-start-date").innerHTML = osaStartDate;
document.getElementById("osa-full-end-date").innerHTML = osaEndtDate;
document.getElementById("osa-full-files").innerHTML = numberWithCommas(osaNumFiles);


 //generate full reports
if (highCount == 0 && medCount == 0 && lowCount == 0 ) {
 document.getElementById("sast-full").setAttribute("style", "display: none");
 } else {
 if (highCount > 0) {
 generateCveTable(SEVERITY.HIGH);
 }
 if (medCount > 0) {
 generateCveTable(SEVERITY.MED);
 }
 if (lowCount > 0) {
 generateCveTable(SEVERITY.LOW);
 }
}

if (osaHighCount == 0 && osaMedCount == 0 && osaLowCount == 0 ) {
    document.getElementById("osa-full").setAttribute("style", "display: none");
} else {
    if (osaHighCount > 0) {
        generateCveTable(SEVERITY.OSA_HIGH);
    }
    if (osaMedCount > 0) {
        generateCveTable(SEVERITY.OSA_MED);
    }
    if (osaLowCount > 0) {
        generateCveTable(SEVERITY.OSA_LOW);
    }
}

//functions
function tooltipGenerator(severity) {
    var threshold = 0;
    var count = 0;
    var thresholdHeight = 0;
    //if severity high - threshold = highThreshold and count = highCount
    //if med - ...
    //if low - ...

    switch (severity) {
        case SEVERITY.HIGH:
            threshold = highThreshold;
            count = highCount;
            break;
        case SEVERITY.MED:
            threshold = medThreshold;
            count = medCount;
            break;
        case SEVERITY.LOW:
            threshold = lowThreshold;
            count = lowCount;
            break;

        case SEVERITY.OSA_HIGH:
            threshold = osaHighThreshold;
            count = osaHighCount;
            break;
        case SEVERITY.OSA_MED:
            threshold = osaMedThreshold;
            count = osaMedCount;
            break;
        case SEVERITY.OSA_LOW:
            threshold = osaLowThreshold;
            count = osaLowCount;
            break;
    }

    //calculate visual height
    thresholdHeight = threshold * 100 / count; //todo- exception?


    return '' +

        '<div class="tooltip-container" style="bottom:calc(' + thresholdHeight + '% - 1px)">' +
        '<div class="threshold-line">' +
        ' ' +
        '</div>' +
        '<div class="threshold-tooltip">' +
        '<div>Threshold</div>' +
        '<div>' + threshold + '</div>' +
        '</div>' +
        '</div>';

}

function generateCveTableTitle(severity) {
    var svgIcon;
    var severityNameTtl;
    var severityCountTtl;

    var svgHighIcon = '<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="23px" height="21px" viewBox="0 0 23 21" version="1.1"> <!-- Generator: Sketch 41.2 (35397) - http://www.bohemiancoding.com/sketch --> <title>high</title> <desc>Created with Sketch.</desc> <defs> <path d="M6.54299421,19 C6.54299421,19 6.05426879,18.5188806 5.34871978,17.7129773 C3.86123349,16.0139175 1.41001114,12.8712609 0.542994209,9.75 C-0.678742762,5.3517469 0.542994209,1 0.542994209,1 L8.04299421,0 L15.5429942,1 C15.5429942,1 16.3322418,3.81124806 16.0076778,7.19836733" id="path-1"></path> <mask id="mask-1" maskContentUnits="userSpaceOnUse" maskUnits="objectBoundingBox" x="0" y="0" width="16.0859884" height="19" fill="white"> <use xlink:href="#path-1"></use> </mask> </defs> <g id="Page-1" stroke="none" stroke-width="1" fill="none" fill-rule="evenodd"> <g id="Jenkins" transform="translate(-602.000000, -537.000000)"> <g id="SAST" transform="translate(272.000000, 180.000000)"> <g id="Vulnerabilities-Stat" transform="translate(246.082552, 0.000000)"> <g id="High" transform="translate(22.425880, 105.921935)"> <g id="high" transform="translate(62.000000, 252.000000)"> <path d="M8.00483672,16.8625579 L8.04299421,0 L0.542994209,1 C0.542994209,1 -0.678742762,5.3517469 0.542994209,9.75 C1.70821884,13.9448087 5.73482423,18.178262 6.4378676,18.8941974 L8.00483672,16.8625579 Z" id="Combined-Shape" fill="#F5F5F5"></path> <use id="Rectangle-40-Copy" stroke="#666666" mask="url(#mask-1)" stroke-width="4" xlink:href="#path-1"></use> <path d="M14.4965773,8.86301041 C14.77461,8.38638292 15.2249744,8.38567036 15.5034227,8.86301041 L21.4965773,19.1369896 C21.77461,19.6136171 21.5500512,20 20.9931545,20 L9.00684547,20 C8.45078007,20 8.22497438,19.6143296 8.50342274,19.1369896 L14.4965773,8.86301041 Z" id="Page-1" fill="#DA2945"></path> <rect id="Rectangle-5" fill="#FFFFFF" x="14" y="12" width="2" height="4"></rect> <rect id="Rectangle-6" fill="#FFFFFF" x="14" y="17" width="2" height="2"></rect> </g> </g> </g> </g> </g> </g> </svg>';
    var svgMedIcon = '<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="23px" height="21px" viewBox="0 0 23 21" version="1.1"> <!-- Generator: Sketch 41.2 (35397) - http://www.bohemiancoding.com/sketch --> <title>medium</title> <desc>Created with Sketch.</desc> <defs> <path d="M6.54299421,19 C6.54299421,19 6.05426879,18.5188806 5.34871978,17.7129773 C3.86123349,16.0139175 1.41001114,12.8712609 0.542994209,9.75 C-0.678742762,5.3517469 0.542994209,1 0.542994209,1 L8.04299421,0 L15.5429942,1 C15.5429942,1 16.3322418,3.81124806 16.0076778,7.19836733" id="path-2"/> <mask id="mask-2" maskContentUnits="userSpaceOnUse" maskUnits="objectBoundingBox" x="0" y="0" width="16.0859884" height="19" fill="white"> <use xlink:href="#path-2"/> </mask> </defs> <g id="Page-1" stroke="none" stroke-width="1" fill="none" fill-rule="evenodd"> <g id="Jenkins" transform="translate(-680.000000, -537.000000)"> <g id="SAST" transform="translate(272.000000, 180.000000)"> <g id="Vulnerabilities-Stat" transform="translate(246.082552, 0.000000)"> <g id="High" transform="translate(22.425880, 105.921935)"> <g id="med" transform="translate(140.000000, 252.000000)"> <path d="M8.00483672,16.8625579 L8.04299421,0 L0.542994209,1 C0.542994209,1 -0.678742762,5.3517469 0.542994209,9.75 C1.70821884,13.9448087 5.73482423,18.178262 6.4378676,18.8941974 L8.00483672,16.8625579 Z" id="Combined-Shape" fill="#F5F5F5"/> <use id="Rectangle-40-Copy" stroke="#666666" mask="url(#mask-2)" stroke-width="4" xlink:href="#path-2"/> <path d="M14.4965773,8.86301041 C14.77461,8.38638292 15.2249744,8.38567036 15.5034227,8.86301041 L21.4965773,19.1369896 C21.77461,19.6136171 21.5500512,20 20.9931545,20 L9.00684547,20 C8.45078007,20 8.22497438,19.6143296 8.50342274,19.1369896 L14.4965773,8.86301041 Z" id="Page-1" fill="#FFB400"/> <rect id="Rectangle-5" fill="#FFFFFF" x="14" y="12" width="2" height="4"/> <rect id="Rectangle-6" fill="#FFFFFF" x="14" y="17" width="2" height="2"/> </g> </g> </g> </g> </g> </g> </svg>';
    var svgLowIcon = '<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="23px" height="21px" viewBox="0 0 23 21" version="1.1"> <!-- Generator: Sketch 41.2 (35397) - http://www.bohemiancoding.com/sketch --> <title>low</title> <desc>Created with Sketch.</desc> <defs> <path d="M6.54299421,19 C6.54299421,19 6.05426879,18.5188806 5.34871978,17.7129773 C3.86123349,16.0139175 1.41001114,12.8712609 0.542994209,9.75 C-0.678742762,5.3517469 0.542994209,1 0.542994209,1 L8.04299421,0 L15.5429942,1 C15.5429942,1 16.3322418,3.81124806 16.0076778,7.19836733" id="path-3"></path> <mask id="mask-3" maskContentUnits="userSpaceOnUse" maskUnits="objectBoundingBox" x="0" y="0" width="16.0859884" height="19" fill="white"> <use xlink:href="#path-3"></use> </mask> </defs> <g id="Page-1" stroke="none" stroke-width="1" fill="none" fill-rule="evenodd"> <g id="Jenkins" transform="translate(-641.000000, -537.000000)"> <g id="SAST" transform="translate(272.000000, 180.000000)"> <g id="Vulnerabilities-Stat" transform="translate(246.082552, 0.000000)"> <g id="High" transform="translate(22.425880, 105.921935)"> <g id="low" transform="translate(101.000000, 252.000000)"> <path d="M8.00483672,16.8625579 L8.04299421,0 L0.542994209,1 C0.542994209,1 -0.678742762,5.3517469 0.542994209,9.75 C1.70821884,13.9448087 5.73482423,18.178262 6.4378676,18.8941974 L8.00483672,16.8625579 Z" id="Combined-Shape" fill="#F5F5F5"></path> <use id="Rectangle-40-Copy" stroke="#666666" mask="url(#mask-3)" stroke-width="4" xlink:href="#path-3"></use> <path d="M14.4965773,8.86301041 C14.77461,8.38638292 15.2249744,8.38567036 15.5034227,8.86301041 L21.4965773,19.1369896 C21.77461,19.6136171 21.5500512,20 20.9931545,20 L9.00684547,20 C8.45078007,20 8.22497438,19.6143296 8.50342274,19.1369896 L14.4965773,8.86301041 Z" id="Page-1" fill="#EFD412"></path> <rect id="Rectangle-5" fill="#FFFFFF" x="14" y="12" width="2" height="4"></rect> <rect id="Rectangle-6" fill="#FFFFFF" x="14" y="17" width="2" height="2"></rect> </g> </g> </g> </g> </g> </g> </svg>';

    switch (severity) {
        case SEVERITY.HIGH:
            svgIcon = svgHighIcon;
            severityNameTtl = "High";
            severityCountTtl = highCount;
            break;

        case SEVERITY.OSA_HIGH:
            svgIcon = svgHighIcon;
            severityNameTtl = "High";
            severityCountTtl = osaHighCount;
            break;

        case SEVERITY.MED:
            svgIcon = svgMedIcon;
            severityNameTtl = "Medium";
            severityCountTtl = medCount;
            break;

        case SEVERITY.OSA_MED:
            svgIcon = svgMedIcon;
            severityNameTtl = "Medium";
            severityCountTtl = osaMedCount;
            break;

        case SEVERITY.LOW:
            svgIcon = svgLowIcon;
            severityNameTtl = "Low";
            severityCountTtl = lowCount;
            break;

        case SEVERITY.OSA_LOW:
            svgIcon = svgLowIcon;
            severityNameTtl = "Low";
            severityCountTtl = osaLowCount;
            break;
    }

    return '' +
        '<div class="full-severity-title">' +
        '<div class="severity-icon">' +
        svgIcon +
        '</div>' +
        '<div class="severity-title-name">' + severityNameTtl + '</div>' +
        '<div class="severity-count">' + severityCountTtl + '</div>' +
        '</div>';
}

function generateSastCveTable(severity) {
    var severityCount;
    var severityCveList;
    var tableElementId = "";

    switch (severity) {
        case SEVERITY.HIGH:
            severityCount = highCount;
            severityCveList = highCveList;
            tableElementId = "sast-cve-table-high";
            break;

        case SEVERITY.MED:
            severityCount = medCount;
            severityCveList = medCveList;
            tableElementId = "sast-cve-table-med";
            break;

        case SEVERITY.LOW:
            severityCount = lowCount;
            severityCveList = lowCveList;
            tableElementId = "sast-cve-table-low";
            break;
    }

    //generate table title
    var severityTitle = generateCveTableTitle(severity);

    //generate table headers
    var tableHeadersNames = {h1: "Vulnerability Type", h2: "##"};
    var tableHeadersElement = generateCveTableHeaders(tableHeadersNames);

    //get container and create table element in it
    document.getElementById(tableElementId + '-container').innerHTML =
        severityTitle +
        '<table id="' + tableElementId + '" class="cve-table sast-cve-table ' + tableElementId + '">' +
        tableHeadersElement +
        '</table>';

    //get the created table
    var table = document.getElementById(tableElementId);

    //add rows to table
    var row;
    for (i = 0; i < severityCveList.length; i++) {
        row = table.insertRow(i + 1);
        row.insertCell(0).innerHTML = severityCveList[i].name;
        row.insertCell(1).innerHTML = severityCveList[i].count;

    }
}

function generateOsaCveTable(severity) {
    var severityCount;
    var severityCveList;
    var tableElementId = "";

    switch (severity) {
        case SEVERITY.OSA_HIGH:
            severityCount = osaHighCount;
            severityCveList = osaHighCveList;
            tableElementId = "osa-cve-table-high";
            break;

        case SEVERITY.OSA_MED:
            severityCount = osaMedCount;
            severityCveList = osaMedCveList;
            tableElementId = "osa-cve-table-med";
            break;

        case SEVERITY.OSA_LOW:
            severityCount = osaLowCount;
            severityCveList = osaLowCveList;
            tableElementId = "osa-cve-table-low";
            break;
    }

    //generate table title
    var severityTitle = generateCveTableTitle(severity);

    //generate table headers
    var tableHeadersNames = {h1: "Vulnerability Type", h2: "Publish Date", h3: "Library"};
    var tableHeadersElement = generateCveTableHeaders(tableHeadersNames);

    //get container and create table element in it
    document.getElementById(tableElementId + '-container').innerHTML =
        severityTitle +
        '<table id="' + tableElementId + '" class="cve-table osa-cve-table ' + tableElementId + '">' +
        tableHeadersElement +
        '</table>';

    //get the created table
    var table = document.getElementById(tableElementId);

    //add rows to table
    var row;
    for (i = 0; i < severityCveList.length; i++) {
        row = table.insertRow(i + 1);
        row.insertCell(0).innerHTML = severityCveList[i].cveName;
        row.insertCell(1).innerHTML = severityCveList[i].publishDate;
        row.insertCell(2).innerHTML = severityCveList[i].libraryName;

    }
}

function generateCveTableHeaders(headers) {
    var ret = "<tr>";

    for (h in headers) {
        ret += '<th>' + headers[h] + '</th>';
    }

    ret += "</tr>";
    return ret;
}

function generateCveTable(severity) {
    switch (severity) {
        case SEVERITY.HIGH:
        case SEVERITY.MED:
        case SEVERITY.LOW:
            generateSastCveTable(severity);
            break;

        case SEVERITY.OSA_HIGH:
        case SEVERITY.OSA_MED:
        case SEVERITY.OSA_LOW:
            generateOsaCveTable(severity);
            break;
    }
}

function numberWithCommas(x) {
    return x.toString().replace(/\B(?=(\d{3})+(?!\d))/g, ",");
}