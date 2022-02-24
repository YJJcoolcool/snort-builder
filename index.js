var rule = "";
var parameters = [];
var contentregex = [0,0];
var content = [];
var regex = [];
const classifications={
    "attempted-admin":"Attempted Administrator Privilege Gain",
    "attempted-user":"Attempted User Privilege Gain",
    "inappropriate-content":"Inappropriate Content was Detected",
    "policy-violation":"Potential Corporate Privacy Violation",
    "shellcode-detect":"Executable code was detected",
    "successful-admin":"Successful Administrator Privilege Gain",
    "successful-user":"Successful User Privilege Gain",
    "trojan-activity":"A Network Trojan was detected",
    "unsuccessful-user":"Unsuccessful User Privilege Gain",
    "web-application-attack":"Web Application Attack",
    "attempted-dos":"Attempted Denial of Service",
    "attempted-recon":"Attempted Information Leak",
    "bad-unknown":"Potentially Bad Traffic",
    "default-login-attempt":"Attempt to login by a default username and password",
    "denial-of-service":"Detection of a Denial of Service Attack",
    "misc-attack":"Misc Attack",
    "non-standard-protocol":"Detection of a non-standard protocol or event",
    "rpc-portmap-decode":"Decode of an RPC Query",
    "successful-dos":"Denial of Service",
    "successful-recon-largescale":"Large Scale Information Leak",
    "successful-recon-limited":"Information Leak",
    "suspicious-filename-detect":"A suspicious filename was detected",
    "suspicious-login":"An attempted login using a suspicious username was detected",
    "system-call-detect":"A system call was detected",
    "unusual-client-port-connection":"A client was using an unusual port",
    "web-application-activity":"Access to a potentially vulnerable web application",
    "icmp-event":"Generic ICMP event",
    "misc-activity":"Misc activity",
    "network-scan":"Detection of a Network Scan",
    "not-suspicious":"Not Suspicious Traffic",
    "protocol-command-decode":"Generic Protocol Command Decode",
    "string-detect":"A suspicious string was detected",
    "uknown":"Unknown Traffic",
    "tcp-connection":"A TCP connection was detected"
}

document.addEventListener('keyup', updateRule)
document.addEventListener('click', updateRule)

function updateRule(){
    rule = "alert ";
    // Protocol
    var protocol = document.getElementById('protocol');
    rule += protocol.options[protocol.selectedIndex].text+" ";
    // Src IP & Port
    rule += document.getElementById('srcip').value+" "+document.getElementById('srcport').value+" ";
    // Direction
    var direction = document.getElementById('direction');
    rule += direction.options[direction.selectedIndex].text+" ";
    // Dst IP & Port
    rule += document.getElementById('dstip').value+" "+document.getElementById('dstport').value+" ";
    // Message
    rule += "(msg: \""+document.getElementById('msg').value+"\"; ";
    // Fragbits
    if (parameters.indexOf('fragbitsarea')!==-1) {
        rule += "fragbits: "+document.getElementById('fragbits').value;
        (document.getElementById('fragbitmodifier').value==="(None)")?null:rule += document.getElementById('fragbitmodifier').value;
        rule+="; ";
    }
    // Fragoffset
    if (parameters.indexOf('fragoffsetarea')!==-1) {
        rule += "fragoffset: "+document.getElementById('fragoffset').value+"; ";
    }
    // Content
    content.forEach((item)=>{
        rule+="content: \""+document.getElementById('content'+item).value+"\"; ";
    });
    // Nocase
    (parameters.indexOf('nocase')!==-1)?rule+="nocase; ":null;
    // HTTP Method
    (parameters.indexOf('http_method')!==-1)?rule+="http_method; ":null;
    // Regex
    regex.forEach((item)=>{
        rule+="pcre: \""+document.getElementById('regex'+item).value+"\"; ";
    });
    // Flow
    if (parameters.indexOf('flow')!==-1) {
        rule+="flow: ";
        var param;
        param = document.getElementById('flowto');
        (param.options[param.selectedIndex].value==="none")?null:rule += param.options[param.selectedIndex].value+", ";
        param = document.getElementById('flowestablishment');
        rule += param.options[param.selectedIndex].value+"; ";
    }
    // Threshold
    if (parameters.indexOf('threshold')!==-1) {
        rule+="threshold: ";
        var param;
        param = document.getElementById('thresholdtype');
        rule += "type "+param.options[param.selectedIndex].value+", ";
        param = document.getElementById('trackby');
        rule += "track "+param.options[param.selectedIndex].value+", ";
        rule += "count "+document.getElementById('count').value+", ";
        rule += "seconds "+document.getElementById('seconds').value+"; ";
    }
    // Classtype, SID & Revision
    rule += "classtype: "+document.getElementById('classtype').value+"; sid: "+document.getElementById('sid').value+"; rev: "+document.getElementById('rev').value+";)";
    document.getElementById('generatedsnort').value = rule;
    rule = rule.replaceAll(/[;|(|)|:]/g,"");
    rule = rule.split(" ");
}

function toggleParam(name,state){
    name = name.substr(6,name.length);
    if (state) {
        document.getElementById(name).style.display="block";
        parameters.push(name);
    } else {
        document.getElementById(name).style.display="none";
        parameters.splice(parameters.indexOf(name), 1)
    }
    updateRule()
}

function addTemplate(type){
    var template = document.getElementById(type+'template');
    var clone = template.cloneNode(true);
    clone.id="";
    if (type==="content"){
        contentregex[0]++;
        content.push(contentregex[0]);
        clone.querySelector("input").id=type+contentregex[0];
    } else {
        contentregex[1]++;
        regex.push(contentregex[1]);
        clone.querySelector("input").id=type+contentregex[1];
    }
    document.getElementById(type+"area").appendChild(clone);
}

function removeElement(type, id){
    document.getElementById(id).parentNode.outerHTML="";
    id = parseInt(id.substr(type.length,10));
    if (type==="content"){
        content.splice(content.indexOf(id), 1);
    } else {
        regex.splice(regex.indexOf(id), 1);
    }
}



// PCAP and Snort Tester
var pcap, rule, numalerts=0, revertpcap;

const pickerOpts = {
    types: [
        {
            description: 'Wireshark Packet Capture',
            accept: {
            'pcap/*': ['.pcap']
            }
        },
    ],
    excludeAcceptAllOption: true,
    multiple: false
};
  
async function getTheFile() {
    // open file picker
    [fileHandle] = await window.showOpenFilePicker(pickerOpts);

    // get file contents
    const fileData = await fileHandle.getFile();
    readFile(fileData)
}

function readFile(file){
    let reader = new FileReader();
    reader.readAsBinaryString(file);
    reader.onload = function(){
        pcap = reader.result
        //console.log(thing)
        pcap=ConvertStringToHex(pcap)
    }
    snortoutput("Sucessfully loaded "+file['name']+". Press 'Run' to test Snort rule.",true)
}

function ConvertStringToHex(str) {
    var arr = "";
    for (var i = 0; i < str.length; i++) {
           var toadd = (str.charCodeAt(i).toString(16)).slice(-4);
           (toadd.length===1)?toadd="0"+toadd:null;
           arr+=toadd;
    }
    return arr;
}

function snortoutput(value,clearoutput=false){
    var snorttest = document.getElementById('snorttest');
    (clearoutput)?snorttest.value=value:snorttest.value+=value;
    snorttest.scrollTop=snorttest.scrollHeight; 
}

function testRule(){
    revertpcap = pcap;
    updateRule();
    console.log("Rule: "+rule);
    // Check if rule is valid
    if (rule.includes("")){
        snortoutput("ERROR: Rule contains empty fields! Please ensure all fields are filled up before running!",true);
        return;
    }
    if (rule[2].includes('/')||rule[5].includes('/')||rule[2].includes('[')||rule[5].includes('[')||rule[3].includes('[')||rule[6].includes('[')){
        snortoutput("ERROR: Sorry! The Snort tester does not support IP Address/Port Ranges/Lists. Please use the actual Snort software to test.",true);
        return;
    }
    // Check if pcap file is loaded
    if (pcap==null){
        snortoutput("ERROR: No pcap file loaded!",true);
        return;
    }
    snortoutput("snort alert started\n\n", true);

    setTimeout(()=>{
        numalerts=0;
        var index=0, findindex=0, length=pcap.length, packetlength, seqnum, headerlen;
        var temp1=0; // console.log("temp1: "+temp1)
        console.log("Traffic size: "+length);
        if (rule[1]==="tcp"){
            while (index<pcap.length){
                console.log("Current index: "+index+"/"+length)
                findindex=pcap.search(/[1-9,a-f]+([1-9,a-f]+000000[1-9,a-f]+000000|\w{2}0000\w{4}0000).+080045/im);
                console.log(findindex)
                if (findindex===-1) {
                    console.log("No more packets!")
                    break;
                } else {
                    temp1++;
                    console.log(pcap.substr(index,100))
                    console.log(findindex)
                    var srcip=[], dstip=[], srcport=[], dstport=[];
                    console.log("temp1: "+temp1)
                    console.log("index: "+index);
                    index=findindex+16;
                    
                    index+=32; // Skip to the IP Length
                    // Get length of packet
                    packetlength=parseInt(pcap.substr(index,4),16);

                    index+=20; // Skip to the Source & Destination Addr
                    packetlength-=20;
                    console.log("index: "+index);

                    // Check Source IP
                    for (var i=0; i<4; i++){
                        srcip.push(parseInt(pcap.substr(index,2),16).toString());
                        index+=2;
                        packetlength-=2;
                    }
                    if (!matchIP(srcip,'s')) {
                        pcap=pcap.substr(index,pcap.length);
                        index=0;
                        continue;
                    };
                    // Check Destination IP
                    for (var i=0; i<4; i++){
                        dstip.push(parseInt(pcap.substr(index,2),16).toString());
                        index+=2;
                        packetlength-=2;
                    }
                    if (!matchIP(dstip,'d')) {
                        pcap=pcap.substr(index,pcap.length);
                        index=0;
                        continue;
                    };

                    // Check Source Port
                    srcport.push(parseInt(pcap.substr(index,4),16).toString());
                    index+=4;
                    packetlength-=4;
                    if (!matchPort(srcport,'s')) {
                        pcap=pcap.substr(index,pcap.length);
                        index=0;
                        continue;
                    };
                    // Check Destination Port
                    dstport.push(parseInt(pcap.substr(index,4),16).toString());
                    index+=4;
                    packetlength-=4;
                    if (!matchPort(dstport,'d')) {
                        pcap=pcap.substr(index,pcap.length);
                        index=0;
                        continue;
                    };

                    // Check Sequence Number
                    seqnum=pcap.substr(index,8);
                    index+=4;
                    packetlength-=4;

                    // Get Header Length
                    index+=8;
                    packetlength-=8;
                    headerlen=parseInt(pcap.substr(index,2),16);
                    index+=headerlen;
                    packetlength-=headerlen; // If packetlength is 0, means no more content
                    console.log("INDEX "+index+" PKTLEN "+packetlength)

                    
                    triggeralert(srcip,srcport,dstip,dstport);
                }
                pcap=pcap.substr(index,pcap.length);
                index=0;
            }
        } else if (rule[1]==="udp"){
            while (index<pcap.length){
                console.log("Current index: "+index+"/"+length)
                findindex = pcap.indexOf("9400000094000000",index);
                if (findindex===-1) {
                    break;
                } else {
                    index=findindex+16;
                    index+=52; // Skip to the Source & Destination Addr

                }
            }
        }
        console.log("Current index: "+index+"/"+length);
        snortoutput("Total number of alerts: "+numalerts)
        pcap = revertpcap;
        return;
    },1000)
}

function matchIP(ip,type){
    var checkip;
    (type==='s')?checkip=rule[2]:checkip=rule[5];
    console.log("IP:"+ip);
    console.log("Check IP:"+checkip);
    if (checkip==="any"){
        return true;
    } else {
        if (checkip.includes("/")) {
            return false;
        } else {
            checkip=checkip.split(".")
            return (JSON.stringify(ip)==JSON.stringify(checkip));
        }
    }
}

function matchPort(port,type){
    var checkport;
    (type==='s')?checkport=rule[3]:checkport=rule[6];
    if (checkport==="any"){
        return true;
    } else {
        if (checkport.includes("/")) {
            return false;
        } else {
            checkport=checkport.split(".")
            return (JSON.stringify(port)==JSON.stringify(checkport));
        }
    }
}

function triggeralert(srcip=["undefined"],srcport="undefined",dstip=["undefined"],dstport="undefined"){
    numalerts++;
    snortoutput("[**] [1:"+rule[rule.length-3]+":"+rule[rule.length-1]+"] "+rule[rule.indexOf('msg')+1].substring(1,rule[rule.indexOf('msg')+1].length-1)+" [**]\n");
    snortoutput("[Classification: "+classifications[rule[rule.length-5]]+"] [Priority: 1]\n");
    var datestring = "", d = new Date();
    var dates = [d.getMonth(),d.getDate(),d.getHours(),d.getMinutes(),d.getSeconds()]
    dates.map((i)=>{
        i = i.toString();
        if (i.length==1){
            i="0"+i;
        }
        return i;
    })
    snortoutput(dates[0]+"/"+dates[1]+"-"+dates[2]+":"+dates[3]+":"+dates[4]+"."+d.getMilliseconds());
    snortoutput(" "+srcip.join('.')+":"+srcport+" -> "+dstip.join('.')+":"+dstport+"\n\n");
}

window.addEventListener("dragover", (e) => {
    e.preventDefault();
    document.getElementById("dragdrop").classList.add('showdragdrop');
});

window.addEventListener("drop", (e) => {
    e.preventDefault();
    document.getElementById("dragdrop").classList.remove('showdragdrop');
    var dropfile =  e.dataTransfer || (e.originalEvent && e.originalEvent.dataTransfer);
    var files = e.target.files || (dropfile && dropfile.files);
    if (files) {
        readFile(files[0]);
    } else {
        snortoutput("ERROR: An unknown error occured when trying to get the file. Please try pressing 'Open PCAP file'")
    }
});

window.addEventListener("dragleave", (e) => {
    document.getElementById("dragdrop").classList.remove('showdragdrop');
});