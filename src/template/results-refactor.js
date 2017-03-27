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

//-------------------------- osa vars --------------------------------------
//Legacy form
var osaEnabled = true;

//libraries - Legacy form
var osaVulnerableAndOutdatedLibs = 456;
var okLibraries = 0;

//thresholds - Legacy form
var osaThresholdsEnabled = false;
var osaHighThreshold = 1;
var osaMedThreshold = 3;
var osaLowThreshold = 5;

//counts - Legacy form
var osaHighCount = 2;
var osaMedCount = 9;
var osaLowCount = 10;


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
    var isThresholdExceeded = true;
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
        '<div class="threshold-tooltip-background">' +
        '<div class="threshold-text">Threshold</div>' +
        '<div class="threshold-number">' + threshold + '</div>' +
        '</div>' +
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